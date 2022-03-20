# Projet AISE

Trois composantes : 
 - *db* : le debugger
 - *libinterposition.so* : récupère l'adresse les fonctions des bibliothèques dynamiques et les transmets à *db*
 - *mk_libinter_h* : convertis *libinterposition.so* en C string qu'il met dans *libinter.h* qui sera include par *db*, ce programme est compilé et lancé par CMake avant la compilation de *db*. Ça permet à *db* de ne pas être dépendant de *libinterposition.so*.

J'utilise *elf.h*, *ptrace* et un peu *dl* (pour *libinterposition.so*).

## **db**

### **load_elf.c** et **load_elf.h**
Contient les fonctions dont dépendent *libinterposition.so* et *db*
 - *load_elf()* : charge l'elf et le map dans la variable global *\*start*
 - *close_elf()* : unmap *\*start*
 - *get_shared_func()* : malloc un tableau de pointeur vers les strings des fonctions des lib dynamiques.

### **main.c**
Contient l'interface utilisateur (simple).
 - *main()* : charge db, gestion de touches
 - *print_usage()*

### **print_elf**
 - *print_symtab()* : print la table des .symtab et .dynsym
 - *print_section_header()*
 - *print_glob_var()* : print les variables globales

### **print_tools.c**
 - *print_rip()* : print l'adresse de rip et la fonction associée.
 - *print_regs()* : print les registres
 - *print_str_eflags()* : print le registre eflags sous forme de string
 - *get_sh_flags()* : utilisé par *print_section_header()*, print le *SHdr.sh_flags* sous forme de string
 - *get_sh_type()* : retourne une string de *SHdr.sh_type*  
 - *get_st_info_type()* : retourne une string de info_type de la table des symboles
 - *get_st_info_bind()*
 - *get_st_info_visibility()*
 - *print_st_shndx()*
 - *print_si_code()* : print siginfo lisiblement
 - *str_syscall()* : dit quel syscall est appelé par un valeur de *rax*

### **print_proc.c**
 - *print_file()* : simple *cat*
 - *print_maps()* : print */proc/child/maps* et la description de ses champs
 - *explore_proc()* : navige dans */proc/child/* et en print le contenu

### **fonctions.c**
 - *init_db()* : lance le child, charge le elf, appel *create_maps_struct()* et *make_addr2str()*
 - *close_db()* : free tous ce qui a été aloué dans le programme
 - *make_addr2str()* : charge les données de *libinterposition.so*, et créé un tableau de correspondance entre adresse et nom de fonctions
 - *addr_to_func_name()* : donne le nom de la fonctions à une adresse donnée
 - *str_to_addr()* : donne l'adresse d'une fonction donnée
 - *print_all_func()* : print la liste des fonctions
 - *create_maps_struct()* : parse le fichier */proc/child/maps* dans une struct, utile pour connaitre l'offset général du programme en mémoire et la provenance d'une fonction à une adresse donnée
 - *free_maps_struct()*
 - *make_backtrace()* : renvoie un tableau des adresse backtrace : rip, rbp+8, next_rbp+8, ...
 - *print_backtrace()* : print le nom, l'adresse et l'offset des fonctions backtrace
 - *print_stack()* : print un nombre donnée de ligne de la stack en partant de rsp
 - *print_ldd()* : print les bibliothèque dynamique (via LD_TRACE_LOADED_OBJECTS)
 - *exec_child()* : créé la lib d'interposition, lui tranmet les args, et lance le programme à debugger en la preloadant, puis supprime la lib
 - *continue_exec()* : continue l'execution du child via ptrace
 - *next_instruction()* : execute l'instruction suivante via ptrace
 - *do_breakpoint()* : scanf, créer un breakpoint 0xCC
 - *remove_breakpoint()*
 - *get_local_func()* : malloc un tableau de pointeur vers les strings des fonctions locales.
 - *print_signal()* : print le signal du child et sa description. précise
 - *sig_handle()* : handle de SIGINT pour free le programme avant de quitter
