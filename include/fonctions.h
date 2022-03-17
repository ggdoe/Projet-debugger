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

//
// void init_input();
// char event_key();
//

void sig_handle(int sig);

pid_t exec_child(char *args[]);
int continue_exec(pid_t child, struct user_regs_struct *regs);

size_t *get_addr_dyn(void *start);
char **get_shared_func(void *start, size_t *size_arr);
char **get_local_func(void *start, size_t **addr_value, size_t *size_arr);
void print_all_func(void *start, size_t * addr_dyn, struct maps *maps, size_t size_maps);
char *addr_to_func_name(size_t addr, void *start, size_t *addr_dyn, struct maps *maps, size_t *offset);

void *load_elf(char *filename);
void close_elf(char *filename, void *start);

void print_ldd(char *args[]);

void print_signal(pid_t child);

size_t *mbacktrace(pid_t child, struct user_regs_struct *regs);
void print_stack(pid_t child, long rsp, long rbp, long max);

void print_symtab(void *start);
void print_section_header(void *start);

struct maps *get_maps_struct(pid_t child, size_t *size_arr);
void free_maps_struct(struct maps **maps, size_t size_maps);
void print_file(char *path);

#endif
