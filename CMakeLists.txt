cmake_minimum_required(VERSION 3.10)

project(sbear)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# c++17 required
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(sbear main.cpp)

add_executable(test test/test.c)