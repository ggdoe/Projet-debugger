#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

#define MAX_GUESS 100

int main()
{
	printf("pid : %d\n", getpid());

	// srand(time(NULL));
	u_int64_t x = (u_int64_t) rand() % (MAX_GUESS + 1);
	// getchar();

	u_int64_t guess = 0;

	while(x != guess){
		printf("Guess --> ");
		scanf("%lu", &guess);
		if(x > guess)
			printf("\t+\n");
		else if(x < guess)
			printf("\t-\n");
	}
	printf("Win ! : %lu\n", guess);

	return 0;
}
