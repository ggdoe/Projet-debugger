#include "tools.h"

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static void print_file(char *path);

extern pid_t child;

void print_file(char *path)
{
	int fd_maps = open(path, O_RDONLY);
	if(fd_maps < 0)
		perror("print_file : open");

	const size_t size_buf = 1<<7;
	char *buf = malloc(size_buf);
	ssize_t nbr_read;

	while((nbr_read = read(fd_maps, buf, size_buf)) > 0){
		write(STDOUT_FILENO, buf, nbr_read);
	}
	
	free(buf);
	close(fd_maps);
}

void print_maps(){
	printf("%8s%-10s%7s %4s %8s %5s %-27s %s\n", "", 
		"Adresse", "", "perm", "Offset", 
		"dev", "inode", "pathname");
	char path_maps[20];
	snprintf(path_maps, 20, "/proc/%d/maps", child);
	print_file(path_maps);
}

void explore_proc()
{
	struct dirent ** cur_dir = NULL;
	int nb_file;
	char path[256];
	char to_open[256];
	size_t nbr_match = 0;
	unsigned char file_type;

	snprintf(path, 256, "/proc/%d/", child);

	scan_dir:
	nb_file = scandir(path, &cur_dir, NULL, alphasort);

	ask_dir:

	// On print les fichiers (sauf les 2 premiers : . et ..)
	for(int i = 2; i < nb_file; i++){
		switch (cur_dir[i]->d_type){
			case DT_DIR: // current entry is a DIR
				printf("\033[95m"); break;
			case DT_REG: // current entry is a FILE
				printf("\033[94m"); break;
			case DT_LNK: // current entry is a symbolic link
				printf("\033[32m"); break;
			default: printf("\033[0m");
		}
		printf("%-17s", cur_dir[i]->d_name);
		if(i%7 == 0) printf("\n");
	}

	// quel fichier veut-on ouvrir ?
	printf("\n \033[91m>\033[33m ");
	scanf("%s", to_open); 
	printf("\033[0m");
	
	// 'q' pour quiter
	if(to_open[0] == 'q' && (to_open[1] == '\0' || to_open[1] == '\n'))
		goto end; 

	// On parcours le dossier pour voir qui match la recherche
	nbr_match = 0;
	for(int i = 2; i < nb_file; i++){
		const char *current_file = cur_dir[i]->d_name;
		size_t cursor = 0;
		bool match = true;

		while(current_file[cursor] != '\0' || to_open[cursor] != '\0'){
			if(to_open[cursor] != current_file[cursor]){
				match = false;
				break;
			}
			cursor++;
		}
		if(match){
			char* dup_path = strdup(path);
			snprintf(path, 256, "%s/%s", dup_path, current_file); // on met à jour le path avec le dossier choisi (ici car on aura plus accès à 'current_file' en dehors de la boucle)
			file_type = cur_dir[i]->d_type; // on enregistre le type de fichier
			nbr_match++;
			free(dup_path);
		}
	}
	// Si il a plusieurs match, on redemande
	if(nbr_match != 1){
		printf("%ld\n", nbr_match);
		printf("\n\033[31mpath incorrect.\n");
		goto ask_dir;
	}

	printf("\n");
	if(file_type != DT_DIR){ // si le path n'est pas un dossier
		print_file(path); // on le print
		printf("\n\n");
		snprintf(path, 256, "/proc/%d", child); // et on revient sur /proc
	}
	goto scan_dir;

	end:
	printf("\033[0m\n");
	free(cur_dir);
}
