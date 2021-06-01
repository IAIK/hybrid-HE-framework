cmake_minimum_required(VERSION 3.4.1)
project(AES)

set(AES_SRCS
  aes.cpp
  block.cpp
  )

add_library(aes STATIC ${AES_SRCS})
target_include_directories(aes PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
