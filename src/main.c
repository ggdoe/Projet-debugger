#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

int main()
{
	// char *pwd = getcwd(NULL, 0);
	// printf("%s\n", pwd);
	// free(pwd);

	pid_t child = fork();

	if(child < 0){
		perror("fork");
		return 1;
	}

	else if(child == 0){ // Child process
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0){
			perror("ptrace TRACEME");
			exit(1);
		}

		raise(SIGSTOP);

		char *args[] = {"./test_segv", NULL};

		printf("fils\n");
		if(execv(args[0], args) < 0){
			perror("execv");
			exit(1);
		}
	}

	int status;
	// waitpid(child, NULL, 0);
	do {
		child = wait( &status );
		printf( "Debugger exited wait()\n" );
		if (WIFSTOPPED( status )){
			printf( "Child has stopped due to signal %d\n",
				WSTOPSIG( status ) );
		}
		if (WIFSIGNALED( status )){
			printf( "Child %ld received signal %d\n",
				(long)child, WTERMSIG(status) );
		}
	} while (!WIFEXITED( status ));

	printf("end\n");
	
	return 0;
}
