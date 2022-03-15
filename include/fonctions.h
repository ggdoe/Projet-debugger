#ifndef FONCTION_H
#define FONCTION_H

#include <dlfcn.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <elf.h>
#include <limits.h>
#include <stdbool.h>
#include <err.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "tools.h"

struct maps {
	size_t addr_start;
	size_t addr_end;
	// int flags;
	//size_t offset; 
	// char minor;
	// char major;
	// int inod;
	char *pathname;
};

pid_t exec_child(char *args[]);

int load_elf(char *filename, void **start);
int close_elf(char *filename, void **start);

size_t *mbacktrace(pid_t child);
void print_signal(pid_t child);

void print_symtab(void *start);
void print_section_header(void *start);

size_t get_maps_struct(pid_t child, struct maps **maps);
void free_maps_struct(struct maps *maps, size_t size_maps);
void print_maps(pid_t child);

#endif
