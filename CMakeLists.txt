cmake_minimum_required(VERSION 3.10)
project("Projet AISE" C)

include_directories("./include/")

add_executable(db src/main.c src/print_symtab.c src/fonction.c src/load_elf.c)

add_executable(test_segv tests/segfault.c)
add_executable(test_pm tests/+-.c)

# target_link_libraries(db dl)
# target_link_libraries(test_segv dl)

add_library(interposition SHARED src/interposition.c src/load_elf.c)
set_property(TARGET interposition PROPERTY POSITION_INDEPENDENT_CODE ON)
target_link_libraries(interposition dl)


target_compile_options(db PRIVATE
                        -Wall -Wextra -pedantic
                        -Wno-unused-result
						# -g
                        # -O3
                        )

target_compile_options(test_segv    PRIVATE -g -O0)
target_compile_options(test_pm      PRIVATE -g -O0)
