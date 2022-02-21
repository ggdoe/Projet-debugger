cmake_minimum_required(VERSION 3.10)
project("Projet AISE" C)

include_directories("include/")

add_executable(db src/main.c)

add_executable(test_segv tests/segfault.c)

target_compile_options(db PRIVATE
                        -Wall -Wextra -pedantic
                        -Wno-unused-result
						# -g
                        # -O3
                        )

target_compile_options(test_segv PRIVATE -g)
