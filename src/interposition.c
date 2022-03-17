#define _GNU_SOURCE
#include <unistd.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <string.h>
#include <signal.h>
#include <execinfo.h>

#include <elf.h>

char **get_shared_func(void *start, size_t *size_arr);
void *load_elf(char *filename);
void close_elf(char *filename, void* start);
// size_t cnt = 0;

// void* (*malloc2)(size_t) = NULL;
// void* (*mmap2)(void *, size_t, int, int, int, off_t);

// void * malloc(size_t size)
// {
// 	cnt +=1;

// 	if(malloc2 == NULL)
// 	{
// 		mmap2 = (void*(*)(void *, size_t, int, int, int, off_t)) 
// 					dlsym( RTLD_DEFAULT, "mmap");
// 		malloc2 = (void*(*)(size_t)) dlsym( RTLD_NEXT, "malloc");
// 		if(!malloc2 || !mmap2)
// 			abort();
// 	}
// 	return malloc2(size);
// }

__attribute__((constructor))
void start_interposition()
{
	void* start = NULL;
	char *args[] = {"./test_segv", NULL};

	start = load_elf(*args); // start est l'adresse du elf
	size_t size_arr;
	char **str_dyn = get_shared_func(start, &size_arr);

	size_t *addr_dyn = malloc(size_arr * sizeof(size_t));

	char buff[128];

	for(size_t i = 0; i < size_arr; i++){

		// on veut pas les @@  (ex : malloc@@GLIBC_2.2.5)
		for(size_t j = 0;; j++){
			buff[j] = str_dyn[i][j]; // copie j-eme caractère
			if(buff[j] == '@'){
				buff[j] = '\0';
				break;
			}
		}
		// on recupere l'addr de la fonction avec pour nom le buff
		addr_dyn[i] = (size_t) dlsym(RTLD_DEFAULT, buff);
		if(!addr_dyn[i])
			printf("Impossible de lire l'addr de %s\n", buff);

		// printf("%-18s -> %#lx\n", buff, addr_dyn[i]);
	}

	int fd = open("addr.data", O_RDWR | O_CREAT, 0600);
	if(fd < 0){
		perror("open (libinterposition.so)");
		exit(1);
	}

	// on redimentionne le fichier
	if(ftruncate(fd, size_arr * sizeof(size_t)) < 0)
	{
		perror("ftruncate");
		abort();
	}

	size_t *mmaped = (size_t*) mmap(NULL, size_arr * sizeof(size_t), 
									PROT_WRITE, MAP_SHARED, fd, 0);

	// on ecrit dans le fichier les addr précédement trouvées
	memcpy(mmaped, addr_dyn, size_arr * sizeof(size_t));
	
	// on ferme tous
	munmap(mmaped, size_arr * sizeof(size_t));
	free(str_dyn);
	free(addr_dyn);
	close_elf(*args, start);

	// on remet un SIGTRAP, le debugger peut reprendre la main
	raise(SIGTRAP);
}

// __attribute__((destructor))
// void end_interposition()
// {
// 	// printf("Count = %lu\n", cnt);
// }

