// #define _GNU_SOURCE

#include "fonctions.h"

int main()
{
	// char *pwd = getcwd(NULL, 0);
	// printf("%s\n", pwd);
	// free(pwd);

	pid_t child;
	char *args[] = {"./test_segv", NULL};
	void* start = NULL;

	child = exec_child(args);

	load_elf(*args, &start);
	print_symtab(start);
	print_section_header(start);
	print_signal(child);
	print_maps(child);
	size_t *arr_backtrace = mbacktrace(child);
	close_elf(*args, &start);

	free(arr_backtrace);
	// printf("end\n");
	return 0;
}
