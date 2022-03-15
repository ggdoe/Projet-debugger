#include "fonctions.h"


size_t get_maps_struct(pid_t child, struct maps **maps) //double pointeur necessaire sinon segfault
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
	char* buff;
	char buff_pathname[128];
	size_t offs;

	size_t sz_alloc_maps = 12; // taille initiale alloué
	size_t i; // nombres d'elements dans la struct maps

	*maps = (struct maps*) malloc(sz_alloc_maps * sizeof(struct maps));
	
	// while ((len_buf=getline(&buf, &size_buf, fd_maps)>0)){
	
	for(i = 0; getline(&buff, &size_buf, fd_maps) > 0; i++)
	{
		if(i >= sz_alloc_maps) // si on manque de place, on double le buffer
			*maps = (struct maps*) realloc(*maps, (sz_alloc_maps <<= 1) * sizeof(struct maps));

		// on insere un null au debut pour fix le cas ou la string (dans maps) est vide, sscanf ne met pas la string à jours
		buff_pathname[0] = '\0';

		// on parse la ligne de /proc/maps
		sscanf(buff, "%12lx-%12lx %*s %08lx %*s %*s %s", 
			&(*maps)[i].addr_start, 
			&(*maps)[i].addr_end, 
			&offs, // on pourrait récupérer offset dans la struct
			buff_pathname
			);

		// on alloue la place pour pathname, (strdup appel malloc)
		(*maps)[i].pathname = strdup(buff_pathname);

		// printf("%s", buff);
		// printf("%012lx-%012lx ---- %08lx --\t\t\t\t %s\n", (*maps)[i].addr_start, (*maps)[i].addr_end, offs, (*maps)[i].pathname);
	}

	return i; // on renvoie le nombre d'element écrit dans struct maps
	return 0;
}

void free_maps_struct(struct maps *maps, size_t size_maps){
	for(size_t i = 0; i < size_maps; i++)
		free(maps[i].pathname); // on free le strdup()
	free(maps);
}

void print_maps(pid_t child)
{
	char path_maps[20];
	snprintf(path_maps, 20, "/proc/%d/maps", child);

	int fd_maps = open(path_maps, O_RDONLY);
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

size_t *mbacktrace(pid_t child)
{
	struct maps *smaps;
	size_t size_maps = get_maps_struct(child, &smaps);
	size_t mem_maps_off = smaps[0].addr_start;
	free_maps_struct(smaps, size_maps);

	// struct stat stat;
	// fstat(fd_maps, &stat);
	// printf("stat.st_size : %ld", stat.st_size);
	
	// voir dladdr() 

	size_t *arr_trace = malloc(128 * sizeof(size_t));

	long return_addr;
	long rbp;

	struct user_regs_struct regs;
	
	// on recupere les registres du child
	if(ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0){
		perror("ptrace(GETREGS)");
		exit(1);
	}
	
	arr_trace[0] = regs.rip;
	rbp = regs.rbp;

	int i = 0;
	while(rbp != 0)
	{
		return_addr = ptrace(PTRACE_PEEKDATA, child, rbp + 8L, NULL);
		rbp = ptrace(PTRACE_PEEKDATA, child, rbp, NULL);
		if((rbp == -1 || return_addr == -1) && errno ){ // catch erreur probable
			perror("ptrace PEEK_DATA");
		}
		arr_trace[++i] = return_addr;
		// if(return_addr < 0x700000000000)
		// 	arr_trace[i] -= mem_maps_off;

	}

	arr_trace[++i] = -1; // fin du tab : 0xffffff...
	
	printf("\nbacktrace :\n");
	for(int j = 0; j < i; j++){
		printf("0x%lx (+0x%lx)\n", arr_trace[j], arr_trace[j] - mem_maps_off);
	}

	printf("\n rip : %llx", regs.rip);
	printf("\n rbp : %llx", regs.rbp);
	printf("\n rsp : %llx\n", regs.rsp);
	// printf(" ret : %lx\n\n", return_addr); // 0x0000555555555249
	
	/* PRINT STACK :
	for(int i = -15; i < 15; i++){
		return_addr = ptrace(PTRACE_PEEKDATA, child, regs.rbp + 8*i, NULL);
		printf("\n %llx - %16lx", regs.rbp + 8*i, return_addr);
		// return_addr = ptrace(PTRACE_PEEKDATA, child, regs.rbp + 8*i+4, NULL);
		// printf("\n %llx - %16lx -", regs.rbp + 8*i+4, return_addr);
		if(i == 0) printf(" <--");
	}
	printf("\n");
	*/

	///////TODO OR DID
	// chercher dans quelle fonction est rip, puis peek new_rbp
	// chercher dans quelle fonction est return_addr, etc

	// ajouter fonction print stackframe (de la mm facon que gdb)
    // tester deadlock
    // afficher variables globales
    // breakpoint
	// compter malloc / mmap (interposé mmap, stocker addr retour...)
	// voir dl_iterate_pdhr
	// explorer /proc/pid/ avec dir_ent voir TD ls

	return arr_trace;
}

pid_t exec_child(char *args[])
{
	pid_t child = fork();
	if(child < 0){
		perror("fork");
		return 1;
	}
	else if(child == 0){
		if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0){
		perror("ptrace TRACEME");
		exit(1);
		}
		if(execv(args[0], args) < 0){
			perror("exec_child() : execv");
			exit(1);
		}
	}
	return child;
}

/*
	Avance l'etat du child jusqu'à la reception d'un signal
		puis donne les infos de ce signal
		puis essaye de continuer l'execution
*/
void print_signal(pid_t child)
{
	const int MAX_LOOP = 10;
	struct user_regs_struct regs, old_regs;
	siginfo_t siginfo, old_siginfo;
	int status;

	for(int i = 0; i < MAX_LOOP; i++){
		old_regs = regs;
		old_siginfo = siginfo;

		ptrace(PTRACE_CONT, child, 0,0);
		wait(&status);

		if (WIFEXITED(status))
			return;

		if(ptrace(PTRACE_GETSIGINFO, child, NULL, &siginfo) < 0){
			perror("ptrace(GETSIGINFO)");
			exit(1);
		}

		if(ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0){
			perror("ptrace(GETREGS)");
			exit(1);
		}

		//probablement useless, plus tard
		if(	!memcmp(&regs, &old_regs, sizeof(struct user_regs_struct)) &&
			!memcmp(&siginfo, &old_siginfo, sizeof(siginfo_t)) )
		{
			// on break car le child est bloqué au même endroit 
			//	que l'itération précédente
			break;
		}

		printf("signal : %s   |   errno : %s   |   code : %d\n", 
						strsignal(siginfo.si_signo), 
						strerror(siginfo.si_errno), 
						siginfo.si_code);

		print_si_code(&siginfo);

		// print_regs(&regs);
		printf("\n%llx\n\n", regs.rip);
	}

}

int load_elf(char *filename, void **start)
{
	int fd;
	struct stat stat;

	fd = open(filename, O_RDONLY);
	if(fd < 0)
		perror("open");

	fstat(fd, &stat);

	*start = mmap(0, stat.st_size, PROT_READ , MAP_FILE | MAP_SHARED, fd, 0);
	if(*start == MAP_FAILED)
	{
		perror("mmap");
		abort();
	}
	close(fd);

	Elf64_Ehdr* hdr = (Elf64_Ehdr *) start;

	if(memcmp(hdr->e_ident, ELFMAG, SELFMAG))
		printf("%s is not a valid elf file.", filename);

	// print_symtab(hdr, sections);
	// print_section_header(hdr, sections);

	// -- readelf / nm / elfutils / libunwind

	return 0;
}

int close_elf(char *filename, void** start)
{
	int fd;
	struct stat stat;

	fd = open(filename, O_RDONLY);
	if(fd < 0)
		perror("open");

	fstat(fd, &stat);
	close(fd);
	munmap(*start, stat.st_size);

	return 0;
}



