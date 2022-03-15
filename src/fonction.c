#include "fonctions.h"


size_t get_maps_offset(pid_t child, bool print)
{
	char path_maps[20];
	snprintf(path_maps, 20, "/proc/%d/maps", child);

	int fd_maps = open(path_maps, O_RDONLY);
	if(fd_maps < 0)
		perror("open");

	const size_t size_buf = 2<<13;
	char *buf = malloc(size_buf);

    // changer pour une boucle
	ssize_t nbr_read = read(fd_maps, buf, size_buf);
	
	if(print)
		write(STDOUT_FILENO, buf, nbr_read);

	size_t mem_maps_off = strtoul(buf, NULL, 16);
	
	free(buf);
	close(fd_maps);

	return mem_maps_off;
}

size_t *mbacktrace(pid_t child)
{
	size_t mem_maps_off = get_maps_offset(child, true);

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
	
	arr_trace[0] = regs.rip;// - mem_maps_off;
	rbp = regs.rbp;

	int i = 0;
	while(rbp != 0)
	{
		return_addr = ptrace(PTRACE_PEEKDATA, child, rbp + 8L, NULL);
		rbp = ptrace(PTRACE_PEEKDATA, child, rbp, NULL);
		if(rbp == -1 || return_addr == -1){ // catch erreur probable
			perror("ptrace PEEK_DATA");
		}
		arr_trace[++i] = return_addr;// - mem_maps_off;
		// if(return_addr < 0x700000000000)
		// 	arr_trace[i] -= mem_maps_off;

	}

	arr_trace[++i] = -1; // fin du tab
	
	printf("\nbacktrace :\n");
	for(int j = 0; j < i; j++){
		printf("0x%lx (+0x%lx)\n", arr_trace[j], arr_trace[j] - mem_maps_off);
	}

	printf("\n rip : %llx", regs.rip);
	printf("\n rbp : %llx", regs.rbp);
	printf("\n rsp : %lx\n", regs.rsp);
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

	// chercher dans quelle fonction est rip, puis peek new_rbp
	// chercher dans quelle fonction est return_addr, etc

	// ajouter fonction print stackframe (de la mm facon que gdb)
    // tester deadlock
    // afficher variables globales
    // breakpoint
	// voir dl_iterate_pdhr

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

int ldd(char *filename)
{
	void* start = NULL;
	int fd;
	struct stat stat;

	fd = open(filename, O_RDONLY);
	if(fd < 0)
		perror("open");

	fstat(fd, &stat);

	start = mmap(0, stat.st_size, PROT_READ , MAP_FILE | MAP_SHARED, fd, 0);
	if(start == MAP_FAILED)
	{
		perror("mmap");
		abort();
	}

	Elf64_Ehdr* hdr = (Elf64_Ehdr *) start;

	if(memcmp(hdr->e_ident, ELFMAG, SELFMAG))
		printf("%s is not a valid elf file.", filename);

	Elf64_Shdr* sections = (Elf64_Shdr *)((char *)start + hdr->e_shoff);

	print_symtab(hdr, sections);
	print_section_header(hdr, sections);

	munmap(start, stat.st_size);
	close(fd);

	// -- readelf / nm / elfutils / libunwind

	return 0;
}

