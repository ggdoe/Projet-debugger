// #define _GNU_SOURCE

#include "tools.h"

void sig_handle(int sig);

int main()
{
	char *args[] = {"./test_segv", NULL};
	char usage[] = "Usage : c s S a m B b# p l r q\n";
	
	// init_db(args) qui appel ces 3 fonctions
	init_db(args);
	signal(SIGINT, sig_handle); // on catch ^C

	printf("%s", usage);

	int quit = 0;
	bool at_start = true;

	while(!quit){
		char key = getchar(); // à ameliorer éventuellement
		printf("---------------------------------------------------------------\n");
		
		switch(key){
			case 'c':
				at_start = false;
				if(!continue_exec()){
					printf("Child finish.\n");
					quit = true;
				}
				print_signal();
				break;
			case 's':
				print_symtab();
				break;
			case 'S':
				print_section_header();
				break;
			case 'a':
				print_all_func();
				break;
			case 'm': // print /proc/child/maps
				{
					printf("TODO\n");
					// printf("%8s%-10s%7s %4s %8s %5s %-27s %s\n", "", 
					// 	"Adresse", "", "perm", "Offset", 
					// 	"dev", "inode", "pathname");
					// char path_maps[20];
					// snprintf(path_maps, 20, "/proc/%d/maps", child);
					// print_file(path_maps);
				}
				break;
			case 'p': // /proc/child/...
				// opendir ... 
				// scanf ...
				// print_file(path)
				break;
			case 'b': //  stack
				{
					size_t max_stack = 5; // nombre de ligne de stack à afficher
					if(scanf("%lu", &max_stack) != 1 // si scanf 
						|| !max_stack) 
						max_stack = 5; // par defaut 5 lignes de stack
					print_stack(0,max_stack);
					fflush(stdin); // tentative pour que scanf ne pollue pas getchar()
				}
				break;
			case 'B': // backtrace
				// if(!at_start)
				// {
				// 	size_t *arr_backtrace = mbacktrace(child, &regs);
				// 	// le dernier élement du tableau est -1
				// 	for(size_t i = 0; arr_backtrace[i] != (size_t)(-1); i++){
				// 		size_t offset;
				// 		char *func_name = addr_to_func_name(arr_backtrace[i], start, addr_dyn, maps, &offset);
				// 		printf("%#lx \t %s (+%#lx)\n", arr_backtrace[i], func_name, offset);
				// 	}
				// 	free(arr_backtrace);
				// }
				break;
			case 'r':
				print_regs();
				break;
			case 'l': // affiche les lib dynamique
				print_ldd();
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

	return 0;
}

void sig_handle(__attribute__((unused)) int sig)
{
	printf("\nq to quit (close, free and kill child)\n");
}
