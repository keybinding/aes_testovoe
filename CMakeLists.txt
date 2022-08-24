cmake_minimum_required(VERSION 3.23)
project(testovoe_zadanie)

set(CMAKE_CXX_STANDARD 20)

add_executable(testovoe_zadanie main.cpp include/aes_consts.h)

include_directories(include)
find_library(SHA256 sha256 lib)
target_link_libraries(testovoe_zadanie LINK_PUBLIC ${SHA256})
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/src.txt DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
