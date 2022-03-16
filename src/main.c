// #define _GNU_SOURCE

#include "fonctions.h"

int main()
{
	pid_t child;
	char *args[] = {"./test_segv", NULL};
	void* start = NULL;
	size_t *arr_backtrace = NULL;
	struct user_regs_struct regs;
	char usage[] = "Usage : c s S m B b r q\n";

	child = exec_child(args);
	load_elf(*args, &start);

	printf("%s", usage);
	if(ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0){
		perror("ptrace(GETREGS)");
		exit(1);
	}
	print_signal(child);


	int quit = 0;

	while(!quit){
		char key = getchar();
		printf("--------------------------------------------------\n");
		switch(key){ // à ameliorer
			case 'c':
				continue_exec(child, &regs);
				print_signal(child);
				break;
			case 's':
				print_symtab(start);
				break;
			case 'S':
				print_section_header(start);
				break;
			case 'm':
				print_maps(child);
				break;
			case 'b': //print stack
				print_stack(child, regs.rsp, regs.rbp, regs.rsp + 8 * 10);
				break;
			case 'B':
				free(arr_backtrace);
				arr_backtrace = mbacktrace(child, &regs);
				for(size_t i = 0; arr_backtrace[i] != (size_t)(-1); i++)
					printf("%lx\n", arr_backtrace[i]);
				break;
			case 'r':
				print_regs(&regs);
				break;
			case 'q':
				quit = 1;
				break;
			default:
				printf("%s", usage);
				break;
		}
	}

	close_elf(*args, &start);
	free(arr_backtrace);
	return 0;
}
