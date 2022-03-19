#ifndef LOAD_ELF_H_
#define LOAD_ELF_H_

#include <sys/types.h>

void load_elf(char *filename);
void close_elf();
char **get_shared_func(size_t *size_arr);

#endif
