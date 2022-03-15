// #define _GNU_SOURCE

#include "fonctions.h"

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
