#include "libinter.h" // binaire de la lib d'interposition

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>

#include "load_elf.h"
#include "tools.h"

static void exec_child();
static char **get_local_func(size_t **addr_list, size_t *size_arr);
static void make_addr2str();
static size_t str_to_addr(const char *str_func);
static void create_maps_struct();
static void free_maps_struct();
static size_t *make_backtrace();
static void sig_handle(int sig);
static void remove_breakpoint();

extern void *start;
extern Elf64_Ehdr* hdr;
extern Elf64_Shdr* sections;

char **args;
pid_t child;

struct user_regs_struct regs;

static struct addr2str {
	size_t addr;
	char *str;
} *addr2str;

static struct maps {
	size_t addr_start;
	size_t addr_end;
	// int flags; size_t offset; char minor; char major; int inod;
	char *pathname;
} *maps;
size_t size_maps;

static struct breakpoint_list{
	size_t addr;
	long old_value;
} *breakpoint_list;
size_t nb_breakpoint;

// Initialise le debuggeur
void init_db(int argc, char *argv[]){
	if(argc < 2){ printf("%s missing file arguments\n", *argv); exit(1);} 

	// on alloue et on remplis le tableau des args du child
	args = malloc(argc * sizeof(char*));
	for(int i = 0; i < argc - 1; i++)
		args[i] = argv[i+1];
	args[argc - 1] = NULL;

	exec_child();
	load_elf(*args);

	create_maps_struct();
	make_addr2str();

	nb_breakpoint = 0;

	signal(SIGINT, sig_handle); // on catch ^C pour free avant de quitter

	// On récupère les registres
	if(ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0){
		perror("init_db : ptrace(GETREGS)");
		exit(1);
	}
	printf("\n  ");
	printf("\033[32mPID : \033[94m%-8d \033[32mPPID : \033[94m%-8d \033[32mGPID : \033[94m%-8u\033[0m\n", child, getpid(), getgid());
	print_signal(); // affiche le sigtrap de ptrace(TRACE_ME)
}

void close_db(){
	kill(child, SIGKILL);

	if(breakpoint_list != NULL)
		free(breakpoint_list);
	free(args);
	free(addr2str);
	free_maps_struct();
	close_elf();
}

// in : addr
// out : str de la func + offset de addr
char *addr_to_func_name(size_t addr, size_t *offset){
	size_t offset_min = -1;
	size_t index_min;

	// on parcours le tableau addr2str et recupere l'index dont l'offset est le min
	for(size_t i = 0; addr2str[i].str != NULL ;i++){
		if(addr - addr2str[i].addr < offset_min){
			offset_min = addr - addr2str[i].addr;
			index_min = i;
		}
	}
	*offset = offset_min;
	return addr2str[index_min].str;
}

// in : str de la func
// out : addr de la func, 0 en cas d'échec
size_t str_to_addr(const char *str_func)
{
	int nombre_match = 0;
	size_t addr;

	// on parcours le tableau addr2str et recupere l'index dont l'offset est le min
	for(size_t i = 0; addr2str[i].str != NULL ;i++){
		size_t cursor = 0;
		bool match = true;
		// on ne peut pas comparer avec strcmp, pas pratique dans le cas ex: malloc@@GLIB_C.so
		// on parcours caractère par caractère, on passe si ca match pas
		while(str_func[cursor] != '\0' && addr2str[i].str[cursor] != '\0'){
			if(str_func[cursor] != addr2str[i].str[cursor]){
				match = false;
				break;
			}
			cursor++;
		}
		if(match){
			addr = addr2str[i].addr;
			nombre_match++;
		}
	}
	// s'il n'y a qu'une fonction match str on renvoit addr sinon 0
	return (nombre_match == 1) ? addr : 0;
}

// créer/alloue le tableau de correspondance : addr <-> func_name
void make_addr2str(){
	size_t size_alloc = 64; // taille initiale
	addr2str = malloc(size_alloc * sizeof(struct addr2str));
	size_t index = 0;

	size_t size_dyn; // on recupère la liste des func dyn
	char **str_func = get_shared_func(&size_dyn);
	
	//////// Fonctions dynamiques
	// On charge les données de lib interposition
	int fd = open("addr.data", O_RDWR, 0600);
	if(fd < 0){
		perror("make_addr2str : open");
		exit(1);
	}
	// On map le fichier en mémoire, plus simple que read
	size_t *addr_dyn = (size_t*) mmap(NULL, size_dyn * sizeof(size_t), 
									PROT_READ, MAP_SHARED, fd, 0);
	if(addr_dyn == MAP_FAILED)
	{
		perror("make_addr2str : mmap");
		abort();
	}
	close(fd);

	// on stocke addr et str dans le même ordre
	for(size_t i = 0; i < size_dyn; i++){
		addr2str[index].addr = addr_dyn[i];
		addr2str[index].str = str_func[i];
		index++;
		if(index >= size_alloc) // si on manque de place, on double
			addr2str = realloc(addr2str, (size_alloc <<= 1) * sizeof(struct addr2str));
	}

	// on supprime le fichier de communication
	munmap(addr_dyn, size_dyn * sizeof(size_t));
	unlink("addr.data");
	free(str_func); // get_shared_func appel malloc


	//////// Fonctions locales
	size_t size_local;
	size_t *addr_local; // on recupère la liste des func locales
	str_func = get_local_func(&addr_local, &size_local);

	// on recupere l'addr de debut des offsets via /proc/maps
	const size_t offset_runtime = maps[0].addr_start;

	for(size_t i = 0; i < size_local; i++){
		addr2str[index].addr = addr_local[i] + offset_runtime;
		addr2str[index].str = str_func[i];
		index++;
		if(index >= size_alloc) // si on manque de place, on double
			addr2str = realloc(addr2str, (size_alloc <<= 1) * sizeof(struct addr2str));
	}
	free(str_func); // get_local_func appel malloc
	free(addr_local);

	// on marque la fin du tableau
	addr2str[index].addr = -1; // 0xfffff..
	addr2str[index].str = NULL;
}

// print la liste des fonctions et leur adresse
void print_all_func(){
	for(struct addr2str *func = addr2str; func->str != NULL; func++)
	{
		char buff[128];
		// on veut pas les @@  (ex : malloc@@GLIBC_2.2.5)
		// on copie à la main jusqu'à tomber sur '@' ou '\0'
		for(size_t j = 0;; j++){
			buff[j] = func->str[j]; // copie j-eme caractère
			if(buff[j] == '@' || buff[j] == '\0'){
				buff[j] = '\0';
				break;
			}
		}
		printf("  \033[33m%-35s  \033[94m%-#20lx\033[0m ", buff, func->addr);

		// print la localisation de l'addr (via /proc/maps)
		for(size_t j = 0; j < size_maps; j++){
			if(maps[j].addr_start <= func->addr && func->addr < maps[j].addr_end)
				printf("\033[95m%s\033[0m", maps[j].pathname);
		}
		printf("\n");
	}
}

// Parse /proc/pid/maps dans une structure struct *maps
void create_maps_struct()
{
	char path_maps[24];
	snprintf(path_maps, 20, "/proc/%d/maps", child);

	// on ouvre maps avec FILE pour profiter de getline()
	FILE *fd_maps=fopen(path_maps, "r");
	if(!fd_maps){
		perror("create_maps_struct : fopen");
		exit(1);
	}

	size_t size_buf = 0;
	char* buff; // buffer de getline()
	char buff_pathname[128]; // buffer extraction du pathname de /maps
	size_t offs; // non utilisé

	size_t sz_alloc_maps = 12; // taille initiale alloué
	size_t i; // nombres d'elements dans la struct maps

	maps = (struct maps*) malloc(sz_alloc_maps * sizeof(struct maps));
	
	// pour chaque ligne de /proc/pid/maps
	for(i = 0; getline(&buff, &size_buf, fd_maps) > 0; i++)
	{
		if(i >= sz_alloc_maps) // si on manque de place, on double
			maps = (struct maps*) realloc(maps, (sz_alloc_maps <<= 1) * sizeof(struct maps));

		// on insere un null au debut pour fix le cas ou la string (dans maps) est vide, sscanf ne met pas la string à jours
		buff_pathname[0] = '\0';

		// on parse la ligne de /proc/maps
		sscanf(buff, "%12lx-%12lx %*s %08lx %*s %*s %s", 
			&(maps)[i].addr_start, // on remplit 
			&(maps)[i].addr_end, 
			&offs, // on pourrait récupérer offset dans la struct
			buff_pathname
			);

		// on alloue la place pour pathname, (strdup appel malloc)
		maps[i].pathname = strdup(buff_pathname);
	}
	size_maps = i;
	free(buff);
	fclose(fd_maps);
}

void free_maps_struct(){
	for(size_t i = 0; i < size_maps; i++)
		free(maps[i].pathname); // on free le strdup()
	free(maps);
}

// renvoie liste des addr backtrace
size_t *make_backtrace()
{
	size_t *backtrace_addr;
	size_t sz_alloc_bt = 8; // alloc initiale
	backtrace_addr = malloc(sz_alloc_bt * sizeof(size_t));

	long return_addr;
	long rbp;
	
	backtrace_addr[0] = regs.rip; // premier élément est rip
	rbp = regs.rbp;

	size_t i = 0;
	while(rbp != 0) // rbp = 0 ==> fin de la stacktrace
	{
		return_addr = ptrace(PTRACE_PEEKDATA, child, rbp + 8L, NULL);
		rbp = ptrace(PTRACE_PEEKDATA, child, rbp, NULL);
		if((rbp == -1 || return_addr == -1) && errno ){ // catch erreur probable
			perror("backtrace - ptrace(PEEKDATA)");
			printf("Continue execution before backtrace\n");
			return NULL;
		}
		// juste en dessous de rbp il y a l'addr de retour
		backtrace_addr[++i] = return_addr;
		if(i >= sz_alloc_bt) // si on manque de place, on double
			backtrace_addr = (size_t*) realloc(backtrace_addr, (sz_alloc_bt <<= 1) * sizeof(size_t));
	}

	backtrace_addr[++i] = -1; // fin du tab : 0xffffff...
	return backtrace_addr;
}

void print_backtrace(){
	size_t *backtrace_addr = make_backtrace();
	if(!backtrace_addr) return;

	// le dernier élement du tableau est -1
	for(size_t i = 0; backtrace_addr[i] != (size_t)(-1); i++){
		size_t func_offset;
		const char* func_name = addr_to_func_name(backtrace_addr[i], &func_offset);

		printf(" \033[94m%#-17lx\033[33m%s \033[95m(+%#lx)\033[0m\n", backtrace_addr[i], func_name, func_offset); 
	}
	free(backtrace_addr);
}

// print la stack depuis rsp
void print_stack(size_t number)
{
	long value;
	unsigned long long rbp = regs.rbp;
	const unsigned long long rsp = regs.rsp;
	printf("\033[94m%16s \033[95m%18s \033[32m%23s", "Addr", "Hex", "Dec");
	
	bool print_ret_addr = false;

	// on parcours la stack, de rsp jusqu'à max
	for(size_t i = 0; i < 8 * number; i += 8){
		value = ptrace(PTRACE_PEEKDATA, child, rsp + i, NULL);
		if((value == -1) && errno ){
			perror("print_stack : ptrace(PEEK_DATA)");
			exit(1);
		} // catch erreur probable
		
		// on affiche la valeurs en Hex et en Dec
		printf("\n\033[94m%#16llx \033[95m%#18lx ", rsp + i, value);

		if(rsp + i == rbp){
			printf("%13s\033[94m rbp\033[0m", ""); // on indique où sont les rbp
			rbp = value; // on recupere le rbp de la precedente stackframe
			print_ret_addr = true;
		}
		else if(print_ret_addr == true){
			size_t func_offset;
			const char* func_name = addr_to_func_name(value, &func_offset);
			printf("%6s\033[33m%s \033[95m(+%#lx)\033[0m", "", func_name, func_offset); 
			print_ret_addr = false;
		}
		else
			printf("\033[32m%23ld", value);
	}
	printf("\033[0m\n");
}

// print ldd via LD_TRACE_LOADED_OBJECTS=1 (man ld.so)
void print_ldd()
{
	pid_t pid_ldd = fork();
	if(pid_ldd < 0){
		perror("print_ldd : fork");
		exit(1);
	}
	else if(pid_ldd == 0){
		// LD_TRACE_LOADED_OBJECTS fait 'ldd' puis termine le process
		// Par contre les info sur les adresses des .so
		// ne sont pas les mêmes que le child principal.
		char *env[] = {"LD_TRACE_LOADED_OBJECTS=1", "LD_VERBOSE=1", NULL};
		execve(args[0], args, env);
		perror("print_ldd : execve");
		exit(1);
	}
	// le child est censé etre terminé après LD_TRACE_LOADED_OBJECTS
	waitpid(pid_ldd, NULL, 0);
}

// execute le child avec les arguments args
void exec_child()
{
	// On créé la libinterposition, on lui met les droits executable
	int fd = open("libinterposition.so", O_RDWR | O_CREAT, 0777);
	if(fd < 0)
		perror("exec_child : open");
	if(ftruncate(fd, SIZE_LIBINTER) < 0)
	{
		perror("exec_child : ftruncate");
		abort();
	}

	// On map le fichier en mémoire
	void *data_lib = mmap(0, SIZE_LIBINTER, PROT_WRITE, MAP_SHARED, fd, 0);
	if(data_lib == MAP_FAILED)
	{
		perror("exec_child : mmap");
		exit(1);
	}
	
	// on copie le binaire de la lib dans le fichier precedement créé
	memcpy(data_lib, DATA_LIBINTER, SIZE_LIBINTER); // warning string length > ‘4095’
	munmap(data_lib, SIZE_LIBINTER);
	close(fd);
	
	// On a besoin de passer les args à la lib, on les transmets par fichier
	FILE *file_args = fopen("args.data", "w");
	for(size_t i = 0;; i++){
		const char * arg = args[i];
		if(arg == NULL) break;
		fprintf(file_args, "%s\0", arg);
	}
	fclose(file_args);
	
	///// 
	child = fork();
	if(child < 0){
		perror("exec_child : fork");
		exit(1);
	}
	else if(child == 0){
		// On preload la lib
		char *env[] = {"LD_PRELOAD=./libinterposition.so", NULL};
		if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0){
			perror("exec_child : ptrace(TRACEME)");
			exit(1);
		}
		execve(args[0], args, env);
		perror("exec_child : execve");
		exit(1);
	}
	wait(NULL); // on attend le sigtrap de PTRACE_ME
	ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
	ptrace(PTRACE_CONT, child, 0,0); // continue pour charger la lib interposée
	wait(NULL); // on attend le signal quand la lib interposée aura fini
	
	// La lib n'est plus necessaire on peut la supprimer
	unlink("libinterposition.so");
}

// Continue l'execution du prgm
// renvoi false si le child est terminé
bool continue_exec(){
	int status;
	ptrace(PTRACE_CONT, child, 0,0);
	wait(&status);

	if (WIFEXITED(status)){
		printf("\033[31mChild finish.\033[0m\n");
		return false;
	}

	// on recupere les registres du child
	if(ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0){
		perror("continue_exec : ptrace(GETREGS)");
		exit(1);
	}

	remove_breakpoint(); // si on a atteint un breakpoint, on le retire
	return true;
}

bool next_instruction(){
	int status;
	ptrace(PTRACE_SINGLESTEP, child, 0,0);
	wait(&status);

	if (WIFEXITED(status)){
		printf("\033[31mChild finish.\033[0m\n");
		return false;
	}

	unsigned long long old_rip = regs.rip;

	// on recupere les registres du child
	if(ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0){
		perror("next_instruction : ptrace(GETREGS)");
		exit(1);
	}
	if(old_rip == regs.rip){ // si l'exec est bloqué, on print le signal
		print_signal();
		printf("\n");
	}
	else print_rip();

	remove_breakpoint(); // si on a atteint un breakpoint, on le retire
	return true;
}

// créé un breakpoint
void do_breakpoint(){
	char func_name[64];
	size_t addr;
	
	printf("\n \033[91m>\033[33m ");
	scanf("%s", func_name); // on récypère le non de la fonction où break
	printf("\033[0m");

	addr = str_to_addr(func_name); // récupère l'addr de la function
	if(addr == 0){ // retourne 0 en cas d'échec
		printf("\033[91mFonction inconnue : %s\n", func_name);
		return;
	}

	// on vérifie qu'une breakpoint n'existe pas déjà au même endroit
	for(size_t i = 0; i < nb_breakpoint; i++)
		if(addr == breakpoint_list[i].addr){
			printf("\033[91mBreakpoint déjà existant : \033[33m%s\033[35m (\033[94m%#lx\033[35m)\033[0m\n", func_name, addr);
			return;
		}

	printf("\033[35mBreakpoint à \033[33m%s\033[35m (\033[94m%#lx\033[35m)\033[0m\n", func_name, addr);

	// on récupère les instructions à l'addr de la fonction
	long old_value = ptrace(PTRACE_PEEKDATA, child, addr, NULL);

	// on alloue la liste des breakpoints
	breakpoint_list = realloc(breakpoint_list, 
				(nb_breakpoint + 1) * sizeof(struct breakpoint_list));
	// on stock l'addr et ce qui est écrit à cette addr
	breakpoint_list[nb_breakpoint].addr = addr;
	breakpoint_list[nb_breakpoint].old_value = old_value;
	nb_breakpoint++;
	
	// on pose le breakpoint en modifiant directement le binaire (en memoire)
	long int3 = (old_value & 0xffffffffffffff00) | 0xcc;
	ptrace(PTRACE_POKEDATA, child, addr, int3);
	
}

void remove_breakpoint(){
	const unsigned long long rip = regs.rip;
	
	for(size_t i = 0; i < nb_breakpoint; i++){
		const size_t addr = breakpoint_list[i].addr;
		const long old_value = breakpoint_list[i].old_value;

		if(rip == addr){// si on a atteint un breakpoint
			// on remet les instructions originales
			ptrace(PTRACE_POKEDATA, child, addr, old_value);
			// et on supprime le breakpoint de la liste
			breakpoint_list[i].addr = 0;
			breakpoint_list[i].old_value = 0;
		}
	}
}

// récupère la liste des fonctions locales
char **get_local_func(size_t **addr_list, size_t *size_arr)
{
	int nb_symbols;
	char *strtab;

	Elf64_Sym *symtab;

	char **str_list;
	size_t size_alloc = 16;

	size_t size_list = 0;
	str_list = (char**) malloc(size_alloc * sizeof(char*));
	*addr_list = (size_t*) malloc(size_alloc * sizeof(size_t));

	for (int i = 0; i < hdr->e_shnum; i++){
		if (sections[i].sh_type == SHT_SYMTAB /*|| sections[i].sh_type == SHT_DYNSYM*/) 
		{
			symtab = (Elf64_Sym *)((char *)start + sections[i].sh_offset);
			nb_symbols = sections[i].sh_size / sections[i].sh_entsize;
			strtab = (char*)((char*)start + sections[sections[i].sh_link].sh_offset);

			for (int j = 0; j < nb_symbols; ++j) {
				// Si le symbole est une fonction et que son adresse
				// est 0, on garde son nom, pour resoudre son adresse avec dlsym
				if(	ELF64_ST_TYPE(symtab[j].st_info) == STT_FUNC && symtab[j].st_value != 0){
						str_list[size_list] = strtab + symtab[j].st_name;
						(*addr_list)[size_list] = symtab[j].st_value;
						size_list++;

						// si on manque de place on reallou 2 fois plus
						if(size_list >= size_alloc){
							size_alloc <<= 1;
							str_list = realloc(str_list, size_alloc * sizeof(char*));
							*addr_list = realloc(*addr_list, size_alloc * sizeof(size_t));
						}
					}
			}
		}
	}
	*size_arr = size_list;
	return str_list;
}

void print_signal()
{
	siginfo_t siginfo;
	
	if(ptrace(PTRACE_GETSIGINFO, child, NULL, &siginfo) < 0){
		perror("print_signal : ptrace(GETSIGINFO)");
		exit(1);
	}

	printf("\033[95m%-24s \033[33m%9s \033[36m%8s\n", "Signal :", "errno :", "code :");
	printf("\033[31m%-24s\033[33m %9s \033[36m%6d\n\033[91m", 
			strsignal(siginfo.si_signo), 
			strerror(siginfo.si_errno), 
			siginfo.si_code
			);
	print_si_code(&siginfo);
	printf("\033[0m\n\n");
	print_rip(); // print regs RIP
}

void sig_handle(__attribute__((unused)) int sig)
{
	close_db(); // on free proprement
	printf("\n");
	exit(0);
}

