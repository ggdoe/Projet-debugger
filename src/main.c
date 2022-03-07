#define _GNU_SOURCE

#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <elf.h>
#include <limits.h>

#include <err.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "tools.h"

int ldd(char *filename);

int main()
{
	// char *pwd = getcwd(NULL, 0);
	// printf("%s\n", pwd);
	// free(pwd);

	pid_t child = fork();
	char *args[] = {"./test_segv", NULL};

	if(child < 0){
		perror("fork");
		return 1;
	}
	else if(child == 0){ // Child process
		if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0){
			perror("ptrace TRACEME");
			exit(1);
		}
		printf("fils\n");
		if(execv(args[0], args) < 0){
			perror("execv");
			exit(1);
		}
	}

	//// ATTACH
	// pid_t pid = 4614;
	// ptrace(PTRACE_ATTACH, pid, 0, 0);

	struct user_regs_struct regs;
	siginfo_t siginfo;

	printf("ldd : %d\n", ldd(*args));

	for(int i = 0; i < 5; i++){
		wait(NULL);

		if(ptrace(PTRACE_GETSIGINFO, child, NULL, &siginfo) < 0){
			perror("ptrace(GETSIGINFO)");
			exit(1);
		}

		if(ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0){
			perror("ptrace(GETREGS)");
			exit(1);
		}

		printf("signal : %s   |   errno : %s   |   code : %d\n", 
				strsignal(siginfo.si_signo), strerror(siginfo.si_errno), 
				siginfo.si_code);

		print_si_code(&siginfo);

		// print_regs(&regs);
		printf("\n%llx\n\n", regs.rip);
		ptrace(PTRACE_CONT, child, 0,0);
	}

	printf("end\n");
	return 0;
}

int ldd(char *filename)
{
	void* start = NULL;
	int fd, nb_symbols;
	struct stat stat;
	char *strtab;

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
	Elf64_Sym* symtab;

	if(memcmp(hdr->e_ident, ELFMAG, SELFMAG))
		printf("%s is not a valid elf file.", filename);

	Elf64_Shdr* sections = (Elf64_Shdr *)((char *)start + hdr->e_shoff);

	int i = 0;
	for (i = 0; i < hdr->e_shnum; i++){
		if (sections[i].sh_type == SHT_SYMTAB) {
			symtab = (Elf64_Sym *)((char *)start + sections[i].sh_offset);
			nb_symbols = sections[i].sh_size / sections[i].sh_entsize;
			strtab = (char*)((char*)start + sections[sections[i].sh_link].sh_offset);
			break;
		}
	}
	for (; i < nb_symbols; ++i) {
		printf("%d: %s\n", i, strtab + symtab[i].st_name);
	}

	// -- readelf / nm / elfutils / libunwind

	return 0;
}
