#ifndef TOOLS_H_
#define TOOLS_H_

#include <elf.h>
#include <signal.h>
#include <stdio.h>

#include <sys/user.h>
#include <stddef.h>
#include <stdbool.h>

// print_tools.c
void print_regs();
void print_rip();
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
void print_glob_var();
// void print_elf_header();
// void print_reloc_table();

// fonction.c
void init_db(int argc, char *argv[]);
void close_db();
bool continue_exec();
bool next_instruction();

void print_stack(size_t number);
void print_ldd();
void print_signal();
void print_all_func();
void print_backtrace();

void do_breakpoint();

char *addr_to_func_name(size_t addr, size_t *offset);
// size_t str_to_addr(const char *str_func);

// print_proc.c
void explore_proc();
void print_maps();


#endif
