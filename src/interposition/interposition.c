#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <signal.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "load_elf.h"

// récupère l'adresse les fonctions des bibliothèques dynamiques et les transmets à db

__attribute__((constructor))
void start_interposition()
{
	// On recupere les args transmis par le debugger
	char *args[32]; // 32 args max
	FILE *file_args = fopen("args.data", "r");
	if(!file_args) perror("lib interposition : fopen");
	size_t nbr_args = 0; size_t sz_buf;
	while(getline(&(args[nbr_args++]), &sz_buf, file_args) > 0);
	args[nbr_args] = NULL;
	fclose(file_args);
	unlink("args.data");

	//
	load_elf(*args);
	size_t size_arr;
	char **str_dyn = get_shared_func(&size_arr);

	// on alloue le tableau des adresses des fonctions dyn
	size_t *addr_dyn = malloc(size_arr * sizeof(size_t));

	// buffer pour retirer les @@ du nom des symboles dyn (de .symtab)
	char buff[128];
	for(size_t i = 0; i < size_arr; i++){
		// on veut pas les @@  (ex : malloc@@GLIBC_2.2.5)
		for(size_t j = 0;; j++){
			buff[j] = str_dyn[i][j]; // copie j-eme caractère
			if(buff[j] == '@' || buff[j] == '\0'){
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

	////
	// On transmet les adresses trouvées via le fichier addr.data
	int fd = open("addr.data", O_RDWR | O_CREAT, 0600);
	if(fd < 0){
		perror("open (libinterposition.so)");
		exit(1);
	}
	// on redimentionne le fichier à la bonne taille
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
	close_elf();

	// on remet un SIGTRAP, le debugger peut reprendre la main
	raise(SIGTRAP);
}
