cmake_minimum_required(VERSION 3.25)
project(petool C)

set(CMAKE_C_STANDARD 17)

add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")

add_executable(petool main.c pe_struct.h Utils.c Utils.h)
