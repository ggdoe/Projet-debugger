#include <elf.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

// #include <errno.h>
// #include <sys/types.h>

void *start;
size_t map_size;

Elf64_Ehdr* hdr;
Elf64_Shdr* sections;

void load_elf(char *filename)
{
	int fd;
	struct stat stat;

	fd = open(filename, O_RDONLY);
	if(fd < 0)
		perror("open");

	fstat(fd, &stat);
	map_size = stat.st_size;

	start = mmap(0, map_size, PROT_READ , MAP_FILE | MAP_SHARED, fd, 0);
	if(start == MAP_FAILED)
	{
		perror("mmap");
		exit(1);
	}
	close(fd);

	hdr = (Elf64_Ehdr *)start;
	sections = (Elf64_Shdr *)((char *)start + hdr->e_shoff);

	if(memcmp(hdr->e_ident, ELFMAG, SELFMAG))
		printf("%s is not a valid elf file.", filename);
}

void close_elf()
{
	munmap(start, map_size);
}

// besoin de cette fonction dans lib interposition
char **get_shared_func(size_t *size_arr)
{
	int nb_symbols;
	char *strtab;

	Elf64_Sym *symtab;

	char **shared_funcs;
	size_t size_alloc = 16;
	*size_arr = 0;

	shared_funcs = (char**) malloc(size_alloc * sizeof(char*));

	bool found = false;
	Elf64_Word tabletype = SHT_SYMTAB; // On cherche d'abord .symtab (avant .dynsym)

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

