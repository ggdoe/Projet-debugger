#include <stdio.h>
#include <stdlib.h>
#define SIZE 10


int main()
{
	int *a;
	int *b = malloc(SIZE * sizeof(int));

	// b[SIZE/2] = *a;
	// b[SIZE*2] = 10;
	
	// printf("exec\n");

	free(b);

	return 0;
}