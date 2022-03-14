#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#define SIZE 10

int bar(int *b);

int mysqr(int x){
	return x*x;
}

int foo(){
	int *a;
	int *b = malloc(SIZE * sizeof(int));
	b[1] = 1/0;
	exit(0);
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