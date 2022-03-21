#include "tools.h"

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

// print /proc/pid/...

static void print_file(char *path);

extern pid_t child;

// cat un fichier
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

// cat maps
void print_maps(){
	printf("%8s%-10s%7s %4s %8s %5s %-27s %s\n", "", 
		"Adresse", "", "perm", "Offset", 
		"dev", "inode", "pathname");
	char path_maps[20];
	snprintf(path_maps, 20, "/proc/%d/maps", child);
	print_file(path_maps);
}

// explore /proc/child/
void explore_proc()
{
	struct dirent ** cur_dir = NULL;
	size_t nb_file;
	char path[256];
	char to_open[256];
	size_t nbr_match = 0;
	size_t index_match;
	bool root_proc = true; // est ce qu'on est dans le dossier /proc/child/

	snprintf(path, 256, "/proc/%d/", child);

	scan_dir:
	nb_file = scandir(path, &cur_dir, NULL, alphasort);

	printf("\n\033[33m%-17s", "q : retour");
	// On print les fichiers (sauf les 2 premiers : . et ..)
	for(size_t i = 2; i < nb_file; i++){
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
	if(to_open[0] == 'q' && to_open[1] == '\0'){
		// si on est pas dans /proc/child
		if(!root_proc){
			root_proc = true;
			snprintf(path, 256, "/proc/%d", child); // on revient sur /proc
			goto scan_dir;
		}
		// sinon
		goto end; 
	}

	// On parcours le dossier pour voir qui match la recherche
	nbr_match = 0;
	int cursor_max = 0;
	for(size_t i = 2; i < nb_file; i++){
		int cursor = 0;

		// On compte le nombre de caractère identique dont \0
		while(to_open[cursor] == cur_dir[i]->d_name[cursor]){
			cursor++;
		}

		// on compte le nombre de match pour une longueur donnée
		if(cursor == cursor_max)
			nbr_match++;
		else if(cursor > cursor_max){
			nbr_match = 1; // si on atteint un nouveau max, nbr match = 1
			cursor_max = cursor;
			index_match = i;
		}
	}
	
	// Si il a plusieurs match, on redemande
	if(nbr_match != 1){
		if(nbr_match == nb_file - 2) nbr_match = 0; // on n'a pas bouclé sur les fichier . et ..
		printf("\n\033[31mpath incorrect. (%ld correspondance)\n", nbr_match);
		goto scan_dir;
	}
	printf("\n");

	// on concatene le path et le fichier/dossier choisi
	char* dup_path = strdup(path);
	snprintf(path, 256, "%s/%s", dup_path, cur_dir[index_match]->d_name); // on met à jour le path avec le dossier choisi (ici car on aura plus accès à 'current_file' en dehors de la boucle)
	
	 // si le path n'est pas un dossier
	if(cur_dir[index_match]->d_type != DT_DIR){
		print_file(path); // on le print
		strcpy(path, dup_path); // on se replace dans le dossier
		printf("\n\n");
		// snprintf(path, 256, "/proc/%d", child); // et on revient sur /proc
	}
	else 
		root_proc = false; // on s'est déplacé dans un dossier

	free(dup_path);
	goto scan_dir;

	//
	end:
	printf("\033[0m\n");
	free(cur_dir);
}
