cmake_minimum_required(VERSION 3.10)
project("Projet AISE" C)

include_directories("./include/")

add_executable(db src/main.c)

add_executable(test_segv tests/segfault.c)
add_executable(test_pm tests/+-.c)

target_link_libraries(db dl)

target_compile_options(db PRIVATE
                        -Wall -Wextra -pedantic
                        -Wno-unused-result
                        -ldl
						# -g
                        # -O3
                        )

target_compile_options(test_segv    PRIVATE -g)
target_compile_options(test_pm      PRIVATE -g)
