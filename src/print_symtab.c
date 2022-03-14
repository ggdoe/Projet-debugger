#include "tools.h"

void print_symtab(Elf64_Ehdr* hdr, Elf64_Shdr* sections){
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
			printf("  Num:    Value          Size Type    Bind   Vis        Ndx Name\n");
			for (int j = 0; j < nb_symbols; ++j) {
				printf("  %3d: %016lx %5ld %s %s %s ", j, 
					symtab[j].st_value, 
					symtab[j].st_size,
					get_st_info_type(symtab[j].st_info),
					get_st_info_bind(symtab[j].st_info),
					// get_st_info_visibility(symtab[j].st_info), 
					get_st_info_visibility(symtab[j].st_other)
					);
				print_st_shndx(symtab[j].st_shndx);
				printf("%s\n", strtab + symtab[j].st_name);
			}
		}
	}
}

void print_section_header(Elf64_Ehdr* hdr, Elf64_Shdr* sections){
	char *sh_strtab;

	// pour afficher le nom de la section
	sh_strtab = (char*)((char*)hdr + sections[hdr->e_shstrndx].sh_offset);
	
	printf("[Nr] Name              Type             Address           Offset\n");
	printf("     Size              EntSize          Flags  Link  Info  Align\n");
	for (int i = 0; i < hdr->e_shnum; i++){
		printf("[%2d] %-16.16s  %-16s %016lx  %08lx\n", i, sh_strtab + sections[i].sh_name, get_sh_type(sections[i].sh_type), 
								sections[i].sh_addr, sections[i].sh_offset);
		// printf(""); 
		// https://github.com/adugast/read_elf/blob/master/src/main.c#L83
		// https://hub.packtpub.com/understanding-elf-specimen/

	}
}