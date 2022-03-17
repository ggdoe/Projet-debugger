#include "fonctions.h"

char *addr_to_func_name(size_t addr, void *start, size_t *addr_dyn, struct maps *maps, size_t *offset){
	// on recupere toutes les fonctions dynamiques
	size_t size_arr;
	char **str_dyn = get_shared_func(start, &size_arr);

	size_t min_dyn = -1, min_local = -1;
	size_t index_dyn, index_local;

	for(size_t i = 0; i < size_arr; i++)
		if(addr - addr_dyn[i]  < min_dyn){
			min_dyn = addr - addr_dyn[i];
			index_dyn = i;
		}

	size_t *addr_local;
	char **str_local = get_local_func(start, &addr_local, &size_arr);

	const size_t offset_local = maps[0].addr_start;

	for(size_t i = 0; i < size_arr; i++)
		if(addr - (addr_local[i] + offset_local)  < min_local){
			min_local = addr - (addr_local[i] + offset_local);
			index_local = i;
		}

	char *func_name;

	if(min_dyn < min_local){
		func_name = str_dyn[index_dyn];
		*offset = min_dyn;
	}
	else{
		func_name = str_local[index_local];
		*offset = min_local;
	}

	free(str_dyn);
	free(str_local);
	free(addr_local);

	return func_name;
}

void print_all_func(void *start, size_t *addr_dyn, struct maps *maps, size_t size_maps){
	size_t size_arr;
	char **str_func = get_shared_func(start, &size_arr);

	printf("Fonctions dynamiques : \n");
	for(size_t i = 0; i < size_arr; i++){
		char buff[128];
		// on veut pas les @@  (ex : malloc@@GLIBC_2.2.5)
		for(size_t j = 0;; j++){
			buff[j] = str_func[i][j]; // copie j-eme caractère
			if(buff[j] == '@'){
				buff[j] = '\0';
				break;
			}
		}
		printf("  %-35s  %-#20lx ", buff, addr_dyn[i]);
		for(size_t j = 0; j < size_maps; j++){
			if(maps[j].addr_start <= addr_dyn[i] && addr_dyn[i] < maps[j].addr_end)
				printf("%s", maps[j].pathname);
		}
			printf("\n");
	}
	free(str_func);

	printf("\nFonctions locales : \n");
	size_t *addr_local;
	str_func = get_local_func(start, &addr_local, &size_arr);

	const size_t offset_local = maps[0].addr_start;
	for(size_t i = 0; i < size_arr; i++){
		const size_t absolue_addr = addr_local[i] + offset_local;
		printf("  %-35s  %-#20lx ", str_func[i], absolue_addr);
		for(size_t j = 0; j < size_maps; j++){
			if(maps[j].addr_start <= absolue_addr && absolue_addr < maps[j].addr_end)
				printf("%s", maps[j].pathname);
		}
			printf("\n");
	}
	free(str_func);
	free(addr_local);
}

size_t *get_addr_dyn(void *start){
	size_t size_arr;
	char **str_dyn = get_shared_func(start, &size_arr);

	// size_t total_size_str = 

	int fd = open("addr.data", O_RDWR, 0600);
	if(fd < 0){
		perror("open");
		exit(1);
	}

	// size_t *addr_dyn = malloc(size_arr * sizeof(size_t));

	size_t *addr_dyn = (size_t*) mmap(NULL, size_arr * sizeof(size_t), 
									PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if(addr_dyn == MAP_FAILED)
	{
		perror("mmap");
		abort();
	}

	// on supprime le fichier de communication

	close(fd);
	free(str_dyn);
	return addr_dyn;
}

void free_addr_dyn(size_t *addr_dyn)
{
	int fd = open("addr.data", O_RDWR, 0600);
	if(fd < 0){
		perror("open addr.data");
		exit(1);
	}
	struct stat stat;
	fstat(fd, &stat);
	close(fd);
	
	munmap(addr_dyn, stat.st_size);
	unlink("addr.data");
}


// Parse /proc/pid/maps dans une structure struct *maps
struct maps *get_maps_struct(pid_t child, size_t *size_arr)
{
	char path_maps[24];
	snprintf(path_maps, 20, "/proc/%d/maps", child);

	// FILE pour profiter de getline()
	FILE *fd_maps=fopen(path_maps, "r");
	if(!fd_maps){
		perror("fopen");
		exit(1);
	}

	size_t size_buf = 0;
	char* buff; // buffer de getline()
	char buff_pathname[128]; // buffer extraction du pathname de getline()
	size_t offs; // non utilisé

	size_t sz_alloc_maps = 12; // taille initiale alloué
	size_t i; // nombres d'elements dans la struct maps

	struct maps *maps = (struct maps*) malloc(sz_alloc_maps * sizeof(struct maps));
	
	// pour chaque ligne de /proc/pid/maps
	for(i = 0; getline(&buff, &size_buf, fd_maps) > 0; i++)
	{
		if(i >= sz_alloc_maps) // si on manque de place, on double le buffer
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

		// à suppr ->
		// printf("%s", buff);
		// printf("%012lx-%012lx ---- %08lx --\t\t\t\t %s\n", (maps)[i].addr_start, (maps)[i].addr_end, offs, (maps)[i].pathname);
	}
	*size_arr = i;
	return maps; // on renvoie le nombre d'element écrit dans struct maps
}

void free_maps_struct(struct maps **maps, size_t size_maps){
	for(size_t i = 0; i < size_maps; i++)
		free((*maps)[i].pathname); // on free le strdup()
	free(*maps);
}

void print_file(char *path)
{
	int fd_maps = open(path, O_RDONLY);
	if(fd_maps < 0)
		perror("open");

	const size_t size_buf = 1<<7;
	char *buf = malloc(size_buf);
	ssize_t nbr_read;

	while((nbr_read = read(fd_maps, buf, size_buf)) > 0){
		write(STDOUT_FILENO, buf, nbr_read);
	}
	
	free(buf);
	close(fd_maps);
}

size_t *mbacktrace(pid_t child, struct user_regs_struct *regs)
{
	// struct maps *smaps;
	// size_t size_maps = get_maps_struct(child, &smaps);
	// size_t mem_maps_off = smaps[0].addr_start;
	// free_maps_struct(&smaps, size_maps);

	// struct stat stat;
	// fstat(fd_maps, &stat);
	// printf("stat.st_size : %ld", stat.st_size);
	
	size_t *arr_trace = malloc(128 * sizeof(size_t));

	long return_addr;
	long rbp;
	
	arr_trace[0] = regs->rip;
	rbp = regs->rbp;

	int i = 0;
	while(rbp != 0)
	{
		return_addr = ptrace(PTRACE_PEEKDATA, child, rbp + 8L, NULL);
		rbp = ptrace(PTRACE_PEEKDATA, child, rbp, NULL);
		if((rbp == -1 || return_addr == -1) && errno ){ // catch erreur probable
			perror("ptrace PEEK_DATA");
		}
		
		arr_trace[++i] = return_addr;
	}

	arr_trace[++i] = -1; // fin du tab : 0xffffff...
	
	// printf("\nbacktrace :\n");
	// for(int j = 0; j < i; j++){
	// 	printf("0x%lx (+0x%lx)\n", arr_trace[j], arr_trace[j] - mem_maps_off);
	// }

	// printf("\n rip : %llx", regs.rip);
	// printf("\n rbp : %llx", regs.rbp);
	// printf("\n rsp : %llx\n", regs.rsp);
	// printf(" ret : %lx\n\n", return_addr); // 0x0000555555555249
	
	return arr_trace;
}

void print_stack(pid_t child, long rsp, long rbp, long max)
{
	long value;

	printf("%16s %18s %23s", "Addr", "Hex", "Dec");
	
	// on parcours la stack, de rsp jusqu'à max
	for(long i = rsp; i < max; i += 8){
		value = ptrace(PTRACE_PEEKDATA, child, i, NULL);
		if((value == -1) && errno ) // catch erreur probable
			perror("ptrace PEEK_DATA");
		
		// on affiche la valeurs en Hex et en Dec
		printf("\n%16lx %#18lx %23ld", i, value, value);


		if(i == rbp){
			printf(" <-- rbp"); // on precise où sont les rbp
			rbp = value; // on recupere le rbp de la precedente stackframe
		}
	}
	printf("\n");
}

void print_ldd(char *args[])
{
	pid_t child = fork();
	if(child < 0){
		perror("fork");
		exit(1);
	}
	else if(child == 0){
		// LD_TRACE_LOADED_OBJECTS demande a faire ldd 
		// au lieu de lancer le programme.
		// Par contre les info sur l'addresse des .so
		// ne sont pas forcément les mêmes que le child
		// principal.
		char *env[] = {"LD_TRACE_LOADED_OBJECTS=1", "LD_VERBOSE=1", NULL};
		execve(args[0], args, env);
		perror("exec_child() : execv");
		exit(1);
	}
	// le child est censé etre terminé après LD_TRACE_LOADED_OBJECTS
	waitpid(child, NULL, 0);
}

pid_t exec_child(char *args[])
{
	pid_t child = fork();
	if(child < 0){
		perror("fork");
		return 1;
	}
	else if(child == 0){
		
		char *env[] = {"LD_PRELOAD=./libinterposition.so", NULL};
		if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0){
		perror("ptrace TRACEME");
		exit(1);
		}
		execve(args[0], args, env);
		perror("exec_child() : execve");
		exit(1);
	}
	wait(NULL); // on attend le sigtrap de PTRACE_ME
	ptrace(PTRACE_CONT, child, 0,0); // on continue pour chargé la lib interposé
	wait(NULL); // on attend le signal quand la lib interposé aura fini
	return child;
}

int continue_exec(pid_t child, struct user_regs_struct *regs){
	int status;
	ptrace(PTRACE_CONT, child, 0,0);
	wait(&status);

	if (WIFEXITED(status)){
		printf("Child finish.\n");
		return 0;
	}

	// on recupere les registres du child
	if(ptrace(PTRACE_GETREGS, child, NULL, regs) < 0){
		perror("ptrace(GETREGS)");
		exit(1);
	}

	return 1;
}

void print_signal(pid_t child)
{
	siginfo_t siginfo;

	if(ptrace(PTRACE_GETSIGINFO, child, NULL, &siginfo) < 0){
		perror("ptrace(GETSIGINFO)");
		exit(1);
	}

	printf("\n%-40s %16s %16s\n", "Signal :", "errno :", "code :");
	printf("%-40s %16s %16d\n", 
			strsignal(siginfo.si_signo), 
			strerror(siginfo.si_errno), 
			siginfo.si_code
			);
	print_si_code(&siginfo);
	printf("\n");
}



