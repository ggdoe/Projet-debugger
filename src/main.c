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
size_t *mbacktrace(pid_t child);
pid_t exec_child(char *args[]);
void print_signal(pid_t child);


int main()
{
	// char *pwd = getcwd(NULL, 0);
	// printf("%s\n", pwd);
	// free(pwd);

	char *args[] = {"./test_segv", NULL};
	pid_t child = exec_child(args);

	printf("ldd : %d\n", ldd(*args));
	print_signal(child);
	mbacktrace(child);

	// printf("end\n");
	return 0;
}



size_t *mbacktrace(pid_t child)
{
	char path_maps[20];
	snprintf(path_maps, 20, "/proc/%d/maps", child);
	printf("%s\n", path_maps);
	int fd_maps = open(path_maps, O_RDONLY);
	if(fd_maps < 0)
		perror("open");
		
	struct stat stat;
	// fstat(fd_maps, &stat);
	// printf("stat.st_size : %ld", stat.st_size);
	char *buf = malloc(10000);
	read(fd_maps, buf, 10000);
	write(STDOUT_FILENO, buf, 10000);
	free(buf);
	// voir dladdr() 


	long int return_addr;
	long int next_rbp;

	struct user_regs_struct regs;
	// on recupere les registres du child
	if(ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0){
		perror("ptrace(GETREGS)");
		exit(1);
	}

	next_rbp = ptrace(PTRACE_PEEKDATA, child, regs.rbp, NULL);
	return_addr = ptrace(PTRACE_PEEKDATA, child, regs.rbp + 8L, NULL);
	if(next_rbp == -1 || return_addr == -1){
		perror("ptrace PEEK_DATA");
	}

	

	printf("\n rip : %llx", regs.rip);
	printf("\n rbp : %llx", regs.rbp);
	printf("\nnrbp : %lx\n", next_rbp);
	printf(" ret : %lx\n\n", return_addr); // 0x0000555555555249
	// regs.rbp
	for(int i = -15; i < 15; i++){
		return_addr = ptrace(PTRACE_PEEKDATA, child, regs.rbp + 8*i, NULL);
		printf("\n %llx - %16lx", regs.rbp + 8*i, return_addr);
		// return_addr = ptrace(PTRACE_PEEKDATA, child, regs.rbp + 8*i+4, NULL);
		// printf("\n %llx - %16lx -", regs.rbp + 8*i+4, return_addr);
		if(i == 0) printf(" <--");
	}
	printf("\n");

	// chercher dans quelle fonction est rip, puis peek new_rbp
	// chercher dans quelle fonction est return_addr, etc

	// ajouter fonction print stackframe

	return NULL;
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
	// print_section_header(hdr, sections);

	munmap(start, stat.st_size);
	close(fd);

	// -- readelf / nm / elfutils / libunwind

	return 0;
}
