# main.c
 - améliorer gestion key
 - preciser usage
 - nettoyer les includes en trop

#####
 - lister les variable globale 
  - table des symbole -> type OBJECT, bind GLOBAL
  - recupérer aussi la size
 - dire dans quelle fonction est rip à la place de sa valeur en hex
 - faire une struct* {size_t addr, char* name}, pour addr_to_name 
 - mettre qqlq variable (genre start, hdr, regs, ...) en global pour eviter les parametre de fonction à ralonge, éventuellement en mettre qqlq une extern mais jpense pas
 - faire une fonction pour init (malloc des variables globales)
 - faire une fonction pour tous free
 - unlink "addr.data" plus tôt
 - faire en sorte que SIGINT free et quitte plutot qu'il dise de faire 'q'

 ----- TRANSMETTRE NOM DU PRGM (et args) A LIB INTERPOSITION
###

# print_symtab.c
 - changer le nom du fichier
 - print_elf_header (https://github.com/adugast/read_elf/blob/master/src/main.c#L83)
 - print_reloc_table 
 
# fonction.c
 - print backtrace
 - dwarf pour faire addr2line https://developer.ibm.com/articles/au-dwarf-debug-format/
 - afficher rip après signal + ligne ou ca bug
 - utiliser get_maps_struct
 
 - chercher dans quelle fonction est rip, puis peek new_rbp
 - chercher dans quelle fonction est return_addr, etc
 - ajouter fonction print stackframe (de la mm facon que gdb) x/10zg
 - tester deadlock
 - afficher variables globales
 - breakpoint
 - compter malloc / mmap (interposé mmap, stocker addr retour...)
 - voir dl_iterate_pdhr
 - explorer /proc/pid/ avec dir_ent voir TD ls
 - voir dladdr() 

# tools.h
 - de nombreuses fonctions ont rien à foutre dans un .h
  - VIRER LES STATIC INLINES DE 9000 OCTETS
