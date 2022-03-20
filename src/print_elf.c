#include "tools.h"

extern Elf64_Ehdr* hdr;
extern Elf64_Shdr* sections;

void print_symtab()
{
	int nb_symbols;
	char *strtab, *sh_strtab;

	Elf64_Sym *symtab;

	// pour afficher le nom de la section
	sh_strtab = (char*)((char*)hdr + sections[hdr->e_shstrndx].sh_offset);
	
	for (int i = 0; i < hdr->e_shnum; i++){

		// Si on trouve une table de symbole exploitable
		if (sections[i].sh_type == SHT_SYMTAB || sections[i].sh_type == SHT_DYNSYM) 
		{
			symtab = (Elf64_Sym *)((char *)hdr + sections[i].sh_offset);
			nb_symbols = sections[i].sh_size / sections[i].sh_entsize;
			strtab = (char*)((char*)hdr + sections[sections[i].sh_link].sh_offset);

			printf("\nSymbol table '%s' contains %d entries:\n", sh_strtab + sections[i].sh_name, nb_symbols);
			printf("  \033[91mNum\033[0m:    \033[94mValue          \033[32mSize \033[35mType\033[0m    Bind   \033[36mVis\033[0m        Ndx \033[33mName\033[0m\n");
			for (int j = 0; j < nb_symbols; ++j) {
				printf("  \033[91m%3d\033[0m: \033[94m%016lx \033[32m%5ld \033[35m%s\033[0m %s \033[36m%s\033[0m ", j, 
					symtab[j].st_value, 
					symtab[j].st_size,
					get_st_info_type(symtab[j].st_info),
					get_st_info_bind(symtab[j].st_info),
					get_st_info_visibility(symtab[j].st_other)
					);
				print_st_shndx(symtab[j].st_shndx);
				printf("\033[33m%s\033[0m\n", strtab + symtab[j].st_name);
			}
		}
	}
}

void print_section_header(){
	char *sh_strtab;

	// pour afficher le nom de la section
	sh_strtab = (char*)((char*)hdr + sections[hdr->e_shstrndx].sh_offset);
	
	printf("\033[91m%4s  \033[33m%-17s \033[35m%-16s \033[94m%-16s \033[32m%-6s \033[36m%-6s \033[90m%s\033[0m\n",
		"[Nr]", "Name", "Type", "Address", "Off", "Size", "ES Flg Lk Inf Al");
	
	for (int i = 0; i < hdr->e_shnum; i++){
		char str_flags[4];
		get_sh_flags(sections[i].sh_flags, str_flags);

		printf("\033[91m[%2d] \033[33m%-17.17s  \033[35m%-16s \033[94m%016lx \033[32m%06lx \033[36m%06lx \033[90m%02lx %3s %2d %3d %2ld\033[0m\n", 
				i, 
				sh_strtab + sections[i].sh_name, 
				get_sh_type(sections[i].sh_type), 
				sections[i].sh_addr, 
				sections[i].sh_offset, 
				sections[i].sh_size, 
				sections[i].sh_entsize,
				str_flags, 
				sections[i].sh_link, 
				sections[i].sh_info, 
				sections[i].sh_addralign
				);
		// https://hub.packtpub.com/understanding-elf-specimen/
	}
}

// TODO : addr + offset
void print_glob_var(){
	int nb_symbols;
	Elf64_Sym *symtab;
	
	for (int i = 0; i < hdr->e_shnum; i++){
		// Les variables globales sont dans .symtab 
		if (sections[i].sh_type == SHT_SYMTAB) 
		{
			symtab = (Elf64_Sym *)((char *)hdr + sections[i].sh_offset);
			nb_symbols = sections[i].sh_size / sections[i].sh_entsize;
			const char *strtab = (char*)((char*)hdr + sections[sections[i].sh_link].sh_offset);

			printf(" \033[94m%18s \033[32m%5s  \033[33m%s\033[0m\n", "Address", "Size", "Name");
			for (int j = 0; j < nb_symbols; ++j) {

				// On n'affiche que les symboles : Object + Global + Visible
				if(ELF64_ST_TYPE(symtab[j].st_info) == STT_OBJECT 
					&& ELF64_ST_VISIBILITY(symtab[j].st_other) == STV_DEFAULT)
				{
					printf(" \033[94m%#018lx \033[32m%5ld  ", 
						symtab[j].st_value, symtab[j].st_size);
					printf("\033[33m%s\033[0m\n", strtab + symtab[j].st_name);
				}
			}
			break;
		}
	}
}
