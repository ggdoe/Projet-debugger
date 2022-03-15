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

int load_elf(char *filename, void **start);
int close_elf(char *filename, void **start);
size_t *mbacktrace(pid_t child);
pid_t exec_child(char *args[]);
void print_signal(pid_t child);
void print_symtab(void *start);
void print_section_header(void *start);


#endif
