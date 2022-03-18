#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdlib.h>

int main(){
    unsigned char *data_lib;
    struct stat stat;

    int fd = open("libinterposition.so", O_RDONLY);
	if(fd < 0)
		perror("open");

	fstat(fd, &stat);

	data_lib = mmap(0, stat.st_size, PROT_READ , MAP_FILE | MAP_SHARED, fd, 0);
	if(data_lib == MAP_FAILED)
	{
		perror("mmap");
		exit(1);
	}
	close(fd);

    FILE *out_h = fopen("../include/libinter.h", "w");
    fprintf(out_h, "#define SIZE_LIBINTER %ld\n", stat.st_size);
    fprintf(out_h, "#define DATA_LIBINTER \"");

    for(int i = 0; i < stat.st_size; i++){
        fprintf(out_h, "\\x%02x", data_lib[i]);
        if(i != 0 && i%20 == 0)
            fprintf(out_h, "\" \\\n\t\"");
    }
    fprintf(out_h, "\"\n");
    fclose(out_h);
    unlink("libinterposition.so");
}
