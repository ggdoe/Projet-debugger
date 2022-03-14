#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#define SIZE 10

int mysqr(int x){
	return x*x;
}

int main()
{
	printf("pid : %d\n", getpid());
	int *a;
	int *b = malloc(SIZE * sizeof(int));
	
	raise(SIGUSR1);
	// raise(SIGUSR2);
	raise(SIGILL);
	b[1] = 1/0;
	// b[1] = 0./0.; // is OK
	b[SIZE/2] = *a;
	// raise(SIGUSR1);
	b[SIZE*2] = 10;
	// raise(SIGUSR1);
	b[1500] = 10;
	// raise(SIGUSR1);
	
	printf("fin\n");

	free(b);

	return 0;
}