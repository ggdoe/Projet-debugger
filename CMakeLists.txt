cmake_minimum_required(VERSION 3.10)
project("Projet AISE" C)

include_directories("./include/")

# On compile la lib d'interposition
add_library(interposition SHARED src/interposition.c src/load_elf.c)
set_property(TARGET interposition PROPERTY POSITION_INDEPENDENT_CODE ON)
target_link_libraries(interposition dl)

# On build le "convertisseur"
add_executable(mk_libinter_h src/mk_libinter_h.c)
add_dependencies(mk_libinter_h interposition)
# On "convertit" la lib en .h
add_custom_target(run_mk_libinter_h COMMAND mk_libinter_h)


add_executable(db src/main.c src/print_symtab.c src/fonction.c src/load_elf.c)

add_executable(test_segv tests/segfault.c)
add_executable(test_pm tests/+-.c)

# target_link_libraries(db dl)
# target_link_libraries(test_segv dl)


add_dependencies(db run_mk_libinter_h)

target_compile_options(db PRIVATE
                        -Wall -Wextra -pedantic
                        -Wno-unused-result
						# -g
                        # -O3
                        )

target_compile_options(test_segv    PRIVATE -g -O0)
target_compile_options(test_pm      PRIVATE -g -O0)
