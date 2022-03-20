cmake_minimum_required(VERSION 3.10)
project("Projet AISE" C)

include_directories("./include/")

# On compile la lib d'interposition
add_library(interposition SHARED src/interposition/interposition.c src/load_elf.c)
set_property(TARGET interposition PROPERTY POSITION_INDEPENDENT_CODE True) 
target_link_libraries(interposition dl)

# On build le "convertisseur"
add_executable(mk_libinter_h src/interposition/mk_libinter_h.c)
add_dependencies(mk_libinter_h interposition) # on build la lib avant le convertisseur
# On "convertit" la lib d'interposition en .h
add_custom_target(run_mk_libinter_h COMMAND mk_libinter_h) # on ajoute la commande pour lancer le convertisseur

add_executable(db   src/main.c src/fonctions.c 
                    src/load_elf.c src/print_elf.c 
                    src/print_tools.c src/print_proc.c)
add_dependencies(db run_mk_libinter_h) # on lance le convertisseur avant avant la conpilation du programme principal

add_executable(test_segv tests/segfault.c)
# add_executable(test_pm tests/+-.c)


target_compile_options(db PRIVATE
                        -Wall -Wextra -pedantic
                        -Wno-overlength-strings #  warning: string length ‘25552’ is greater than the length ‘4095’ ISO C99 compilers are required to support
                        -Wno-format-contains-nul # '\0' dans exec_child()
                        # -Wno-unused-result
						# -g
                        # -O3
                        )

target_compile_options(test_segv    PRIVATE -g)
# target_compile_options(test_pm      PRIVATE -g)
