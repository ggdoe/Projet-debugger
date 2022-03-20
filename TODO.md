# main.c
 >- améliorer gestion key
 >- preciser usage
 >- nettoyer les includes en trop

#####
 >- lister les variable globale 
 > - table des symbole -> type OBJECT, bind GLOBAL
 > - recupérer aussi la size
 >- dire dans quelle fonction est rip à la place de sa valeur en hex
###

# print_symtab.c
 >- changer le nom du fichier
 >- print_elf_header (https://github.com/adugast/read_elf/blob/master/src/main.c#L83)
 >- print_reloc_table 
 
# fonction.c
 >- print backtrace
 - dwarf pour faire addr2line https://developer.ibm.com/articles/au-dwarf-debug-format/
 >- afficher rip après signal + ligne ou ca bug
 >- utiliser get_maps_struct
 
 >- chercher dans quelle fonction est rip, puis peek new_rbp
 >- chercher dans quelle fonction est return_addr, etc
 >- ajouter fonction print stackframe (de la mm facon que gdb) x/10zg
 >- tester deadlock
 >- afficher variables globales
 >- breakpoint
 >- compter malloc / mmap (interposé mmap, stocker addr retour...)
 >- voir dl_iterate_pdhr
 >- explorer /proc/pid/ avec dir_ent voir TD ls
 >- voir dladdr() 
