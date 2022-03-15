#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <execinfo.h>

#define SIZE 10

int bar(int *b);

int mysqr(int x){
	return x*x;
}

int foo(){
	int *a;
	int *b = malloc(SIZE * sizeof(int));

	// void *buff[1024];
	// char **bt_sym;
	// int sz = backtrace(buff, 1024);
	// bt_sym = backtrace_symbols(buff, sz);
	// for(int i = 0; i < sz; i++)
	// 	printf("%016llx \t %s\n", buff[i], bt_sym[i]);

	b[1] = 1/0;
	// b[1] = 0./0.; // is OK
	b[2] = mysqr(4);
	b[SIZE/2] = *a;
	raise(SIGUSR1);
	bar(b);

}
int bar(int *b){

	raise(SIGUSR2);
	raise(SIGILL);

	// raise(SIGUSR1);
	b[SIZE*2] = 10;
	// raise(SIGUSR1);
	b[1500] = 10;
	// raise(SIGUSR1);
	free(b);
}

int main()
{
	printf("pid : %d\n", getpid());
	foo();
	printf("fin\n");
	return 0;
}