# main.c
 - améliorer gestion key
 - preciser usage
 - nettoyer les includes en trop

 - utiliser dladdr : fork execve preload .so constructor mmap shared


 ###### DONE
 - ordonner l'addr des func dans la table des sym
 - au runtime execve dlsym des func dont addr = 0x0000.. (ou juste celles de .dynsym)
 - utiliser ces addr pour donner le nom des fonction dans backtrace && rip

 - fonction get_runtime_addr()
    -- struct partagée
  - mmap fd (out.data) shared
	- 4 octet : nombre de func (avec addr = 0x000..)
	- liste des nom de fonctions
  - child fstat mmap out.data
	- mmap in.data shared
	- retourne liste des addr dans l'ordre
  - pere waitpid()
	mmap in.data read malloc (pour free plus simple)
 ######

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
