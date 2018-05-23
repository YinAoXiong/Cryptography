cmake_minimum_required(VERSION 3.10)
project(Cryptography)

set(CMAKE_CXX_STANDARD 11)

add_executable(Cryptography main.cpp AES.cpp AES.h)