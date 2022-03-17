#include <elf.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

void *load_elf(char *filename)
{
	void *start = NULL;
	int fd;
	struct stat stat;

	fd = open(filename, O_RDONLY);
	if(fd < 0)
		perror("open");

	fstat(fd, &stat);

	start = mmap(0, stat.st_size, PROT_READ , MAP_FILE | MAP_SHARED, fd, 0);
	if(start == MAP_FAILED)
	{
		perror("mmap");
		exit(1);
	}
	close(fd);

	Elf64_Ehdr* hdr = (Elf64_Ehdr *) start;

	if(memcmp(hdr->e_ident, ELFMAG, SELFMAG))
		printf("%s is not a valid elf file.", filename);

	return start;
}

void close_elf(char *filename, void* start)
{
	int fd;
	struct stat stat;

	fd = open(filename, O_RDONLY);
	if(fd < 0)
		perror("open");

	fstat(fd, &stat);
	close(fd);
	munmap(start, stat.st_size);
}

char **get_shared_func(void *start, size_t *size_arr)
{
	int nb_symbols;
	char *strtab;

	Elf64_Ehdr* hdr = (Elf64_Ehdr *) start;
	Elf64_Shdr* sections = (Elf64_Shdr *)((char *)start + hdr->e_shoff);
	Elf64_Sym *symtab;

	char **shared_funcs;
	size_t size_alloc = 16;
	*size_arr = 0;

	shared_funcs = (char**) malloc(size_alloc * sizeof(char*));

	bool found = false;
	Elf64_Word tabletype = SHT_SYMTAB;

	redo:
	for (int i = 0; i < hdr->e_shnum; i++){
		if (sections[i].sh_type == tabletype) 
		{
			found = true;
			symtab = (Elf64_Sym *)((char *)start + sections[i].sh_offset);
			nb_symbols = sections[i].sh_size / sections[i].sh_entsize;
			strtab = (char*)((char*)start + sections[sections[i].sh_link].sh_offset);

			for (int j = 0; j < nb_symbols; ++j) {
				// Si le symbole est une fonction et que son adresse
				// est 0, on garde son nom, pour resoudre son adresse avec dlsym
				if(	ELF64_ST_TYPE(symtab[j].st_info) == STT_FUNC && symtab[j].st_value == 0){
						shared_funcs[(*size_arr)++] = strtab + symtab[j].st_name;

						// si on manque de place on reallou 2 fois plus
						if(*size_arr >= size_alloc)
							shared_funcs = realloc(shared_funcs, (size_alloc <<= 1) * sizeof(char*));
					}
			}
		}
	}
	if(!found){// si on a pas trouver la table des symboles
		tabletype = SHT_DYNSYM; // on cherche la table des symboles dynamique
		found = true; // true pour eviter boucle infini si il n'y a pas de table des symboles
		goto redo;
	}

	return shared_funcs;
}

// TODO à deplacer autre part
char **get_local_func(void *start, size_t **addr_value, size_t *size_arr)
{
	int nb_symbols;
	char *strtab;

	Elf64_Ehdr* hdr = (Elf64_Ehdr *) start;
	Elf64_Shdr* sections = (Elf64_Shdr *)((char *)start + hdr->e_shoff);
	Elf64_Sym *symtab;

	char **local_funcs;
	size_t size_alloc = 16;

	size_t index = 0;
	
	local_funcs = (char**) malloc(size_alloc * sizeof(char*));
	*addr_value = (size_t*) malloc(size_alloc * sizeof(size_t));

	for (int i = 0; i < hdr->e_shnum; i++){
		if (sections[i].sh_type == SHT_SYMTAB /*|| sections[i].sh_type == SHT_DYNSYM*/) 
		{
			symtab = (Elf64_Sym *)((char *)start + sections[i].sh_offset);
			nb_symbols = sections[i].sh_size / sections[i].sh_entsize;
			strtab = (char*)((char*)start + sections[sections[i].sh_link].sh_offset);

			for (int j = 0; j < nb_symbols; ++j) {
				// Si le symbole est une fonction et que son adresse
				// est 0, on garde son nom, pour resoudre son adresse avec dlsym
				if(	ELF64_ST_TYPE(symtab[j].st_info) == STT_FUNC && symtab[j].st_value != 0){
						local_funcs[index] = strtab + symtab[j].st_name;
						(*addr_value)[index] = symtab[j].st_value;
						index++;

						// si on manque de place on reallou 2 fois plus
						if(index >= size_alloc){
							size_alloc <<= 1;
							local_funcs = realloc(local_funcs, size_alloc * sizeof(char*));
							*addr_value = realloc(*addr_value, size_alloc * sizeof(size_t));
						}
					}
			}
		}
	}
	*size_arr = index;
	return local_funcs;
}
