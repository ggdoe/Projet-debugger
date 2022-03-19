#ifndef TOOLS_H_
#define TOOLS_H_

// #include <stdlib.h>
// #include <string.h>

#include <elf.h>
#include <stdio.h>
#include <signal.h>
#include <sys/user.h>
#include <stdbool.h>

// print_tools.c
void print_regs();
void get_sh_flags(Elf64_Xword sh_flags, char* str_flags);
const char* get_sh_type(Elf64_Word sh_type);
const char* get_st_info_type(unsigned char st_info);
const char* get_st_info_bind(unsigned char st_info);
const char* get_st_info_visibility(unsigned char st_other);
void print_st_shndx(Elf64_Section ndx);
void print_si_code(siginfo_t *siginfo);

// print_elf.c
void print_symtab();
void print_section_header();
// void print_elf_header();
// void print_reloc_table();

// fonction.c
void init_db(char *child_args[]);
void close_db();
bool continue_exec();
void print_stack(size_t addr, size_t number);
void print_ldd();
void print_signal();
void print_file(char *path);
void print_all_func();

// char *addr_to_func_name(size_t addr, size_t *offset);
// size_t str_to_addr(const char *str_func);

#endif
