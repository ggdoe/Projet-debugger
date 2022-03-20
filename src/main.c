// #define _GNU_SOURCE
#include "tools.h"

static void print_usage();

int main(int argc, char *argv[])
{
	init_db(argc, argv);

	print_usage();
	printf("---------------------------------------------------------------\n");
		
	bool quit = 0;

	while(!quit){
		printf("\033[33m");
		char key = getchar();
		printf("\033[0m---------------------------------------------------------------\n");

		switch(key){
			case 'c':
				if(!continue_exec())
					quit = true;
				else
					print_signal();
				break;
			case 'n': // next instruction
				if(!next_instruction())
					quit = true;
				break;
			case 'b': // breakpoint
				do_breakpoint();
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
				print_maps();
				break;
			case 'v': // print global variables
				print_glob_var();
				break;
			case 'p': // /proc/child/...
				explore_proc();
				print_usage();
				break;
			case 'x': //  stack
				{
					size_t max_stack = 5; // nombre de ligne de stack à afficher
					if(scanf("%lu", &max_stack) != 1 // si scanf 
						|| !max_stack) 
						max_stack = 5; // par defaut 5 lignes de stack
					print_stack(max_stack); 
					fflush(stdin); // tentative pour que scanf ne pollue pas getchar()
				}
				break;
			case 'B': // backtrace
				print_backtrace();
				break;
			case 'r':
				print_regs();
				break;
			case 'l': // affiche les lib dynamique
				print_ldd();
				break;
			case 'q':
				quit = true;
				break;
			case '\n': break;
			case 'h': case '\0': default:
				print_usage();
				break;
		}
	}

	close_db();
	return 0;
}

void print_usage(){
	printf( " \033[32mc\033[94m  : continue execution\n" \
			" \033[32mn\033[94m  : next instruction\n" \
			" \033[32mb\033[95m#\033[94m : breakpoint (\033[95m#\033[94m is function name)\n" \
			" \033[32ms\033[94m  : print symbole table\n" \
			" \033[32mS\033[94m  : print section header\n" \
			" \033[32ma\033[94m  : print all functions\n" \
			" \033[32mv\033[94m  : print globals variables\n" \
			" \033[32mm\033[94m  : print /proc/maps\n" \
			" \033[32mp\033[94m  : explore /proc\n" \
			" \033[32mx\033[95m#\033[94m : print stack from rbp (\033[95m#\033[94m is number of line)\n" \
			" \033[32mB\033[94m  : print backtrace\n" \
			" \033[32mr\033[94m  : print registers\n" \
			" \033[32ml\033[94m  : print ldd\n" \
			" \033[32mq\033[94m  : quit\n" \
			" \033[32mh\033[94m  : help\033[0m\n");
}
