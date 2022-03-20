#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdlib.h>

// convertis libinterposition.so en C string 
// et la met dans libinter.h dont dépend db

int main(){
	struct stat stat;

	int fd = open("libinterposition.so", O_RDONLY);
	if(fd < 0)
		perror("mk_lib_h : open");

	fstat(fd, &stat);

	unsigned char *data_lib; // unsigned important sinon fprintf fait nimportequoi (ecrit 0xfffffe3 au lieu de 0xe3)
	
	data_lib = mmap(0, stat.st_size, PROT_READ , MAP_SHARED, fd, 0);
	if(data_lib == MAP_FAILED)
	{
		perror("mk_lib_h : mmap");
		exit(1);
	}
	close(fd);

    // On créé le fichier .h qui contient libinterposition.so
	FILE *lib_h = fopen("../include/libinter.h", "w");
	fprintf(lib_h, "#define SIZE_LIBINTER %ld\n", stat.st_size);
	fprintf(lib_h, "#define DATA_LIBINTER \"");

	for(int i = 0; i < stat.st_size; i++){
		fprintf(lib_h, "\\x%02x", data_lib[i]);
		if(i != 0 && i%20 == 0)
			fprintf(lib_h, "\" \\\n\t\"");
	}
	fprintf(lib_h, "\"\n");
	fclose(lib_h);

    // on peut maintenant supprimer libinterposition.so
	unlink("libinterposition.so");

	return 0;
}
