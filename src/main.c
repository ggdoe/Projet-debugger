// #define _GNU_SOURCE

#include "fonctions.h"

int main()
{
	pid_t child;
	char *args[] = {"./test_segv", NULL};
	void* start = NULL;
	char usage[] = "Usage : c s S a m B b# p l r q\n";

	struct user_regs_struct regs;
	size_t *addr_dyn; // addr des fonctions lib dynamic
	
	child = exec_child(args);
	start = load_elf(*args); // start est l'adresse du elf
	addr_dyn = get_addr_dyn(start);

	signal(SIGINT, sig_handle); // on catch ^C

	printf("%s", usage);
	if(ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0){
		perror("ptrace(GETREGS)");
		exit(1);
	}
	print_signal(child); // affiche le sigtrap de ptrace(TRACE_ME)

	size_t size_maps;
	struct maps *maps = get_maps_struct(child, &size_maps);

	int quit = 0;
	bool at_start = true;

	while(!quit){
		char key = getchar(); // à ameliorer éventuellement
		printf("---------------------------------------------------------------\n");
		
		switch(key){
			case 'c':
				at_start = false;
				continue_exec(child, &regs);
				print_signal(child);
				break;
			case 's':
				print_symtab(start);
				break;
			case 'S':
				print_section_header(start);
				break;
			case 'a':
				print_all_func(start, addr_dyn, maps, size_maps);
				break;
			case 'm': // print /proc/child/maps
				{
					printf("%8s%-10s%7s %4s %8s %5s %-27s %s\n", "", 
						"Adresse", "", "perm", "Offset", 
						"dev", "inode", "pathname");
					char path_maps[20];
					snprintf(path_maps, 20, "/proc/%d/maps", child);
					print_file(path_maps);
				}
				break;
			case 'p': // /proc/child/...
				// opendir ... 
				// scanf ...
				// print_file(path)
				break;
			case 'b': //  stack
				{
					unsigned int max_stack; // nombre de ligne de stack à afficher
					scanf("%u", &max_stack); // vraiment à la zob
					if(!max_stack) max_stack = 5; // par defaut 5 lignes de stack
					print_stack(child, regs.rsp, regs.rbp, regs.rsp + 8 * max_stack);
					fflush(stdin); // tentative pour que scanf ne pollue pas getchar()
				}
				break;
			case 'B': // backtrace
				if(!at_start)
				{
					size_t *arr_backtrace = mbacktrace(child, &regs);
					// le dernier élement du tableau est -1
					for(size_t i = 0; arr_backtrace[i] != (size_t)(-1); i++){
						size_t offset;
						char *func_name = addr_to_func_name(arr_backtrace[i], start, addr_dyn, maps, &offset);
						printf("%#lx \t %s (+%#lx)\n", arr_backtrace[i], func_name, offset);
					}
					free(arr_backtrace);
				}
				break;
			case 'r':
				print_regs(&regs);
				break;
			case 'l': // affiche les lib dynamique
				print_ldd(args);
				break;
			case 'q':
				quit = 1;
				break;
			case '\n': break;
			case 'h': case '\0': default:
				printf("%s", usage);
				break;
		}
	}

	kill(child, SIGKILL);
	free_maps_struct(&maps, size_maps);
	free_addr_dyn(addr_dyn);
	close_elf(*args, &start);
	return 0;
}

void sig_handle(__attribute__((unused)) int sig)
{
	printf("\nq to quit (close, free and kill child)\n");
}
