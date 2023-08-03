cmake_minimum_required(VERSION 3.25)
project(petool C)

set(CMAKE_C_STANDARD 17)

add_executable(petool main.c pe_struct.h)
