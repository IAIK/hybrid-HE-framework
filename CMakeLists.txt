cmake_minimum_required(VERSION 3.10)
project(symhe)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_STANDARD 17)

option(BUILD_TESTS "Build tests for HHE" ON)

# Select ciphers to benchmark
set(PLAIN_CIPHS
  he_only
  he_only_z2
  agrasta
  agrasta_packed
  rasta_5
  rasta_5_packed
  rasta_6
  rasta_6_packed
  dasta_5
  dasta_5_packed
  dasta_6
  dasta_6_packed
  lowmc
  filip_1216
  filip_1280
  kreyvium
  kreyvium_12
  kreyvium_13
  pasta_3
  pasta_4
  pasta2_3
  pasta2_4
  masta_4
  masta_5
  hera_5
)

set(SEAL_CIPHS
  he_only
  agrasta
  rasta_5
  rasta_6
  dasta_5
  dasta_6
  lowmc
  filip_1216
  filip_1280
  kreyvium
  kreyvium_12
  kreyvium_13
  pasta_3
  pasta_4
  pasta2_3
  pasta2_4
  masta_4
  masta_5
  hera_5
)

set(HELIB_CIPHS
  he_only
  agrasta
  agrasta_packed
  rasta_5
  rasta_5_packed
  rasta_6
  rasta_6_packed
  dasta_5
  dasta_5_packed
  dasta_6
  dasta_6_packed
  lowmc
  filip_1216
  filip_1280
  kreyvium
  kreyvium_12
  kreyvium_13
  pasta_3
  pasta_4
  pasta2_3
  pasta2_4
  masta_4
  masta_5
  hera_5
)

set(TFHE_CIPHS
  he_only_z2
  agrasta
  rasta_5
  rasta_6
  dasta_5
  dasta_6
  lowmc
  filip_1216
  filip_1280
  kreyvium
  kreyvium_12
  kreyvium_13
)

include(CheckCCompilerFlag)
function(check_c_compiler_flag_and_add flag result)
  check_c_compiler_flag("${flag}" ${result})
  if(${result})
    add_compile_options("${flag}")
  endif()
endfunction()

# check_c_compiler_flag_and_add(-pedantic CC_SUPPORTS_PEDANTIC)
# check_c_compiler_flag_and_add(-Wall CC_SUPPORTS_WALL)
# check_c_compiler_flag_and_add(-Wextra CC_SUPPORTS_WEXTRA)
# check_c_compiler_flag_and_add(-Wshadow CC_SUPPORTS_WSHADOW)
# check_c_compiler_flag_and_add(-Werror=vla CC_SUPPORTS_ERRORVLA)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Choose the type of build." FORCE)
endif()

# for AES code
if(MSVC)
  add_definitions("-DOC_ENABLE_SSE2")
  message("-- Enabling SSE2 for AES")
  add_definitions("-DOC_ENABLE_AESNI")
  message("-- Enabling AES_NI")
else()
  check_c_compiler_flag_and_add(-msse2 CC_SUPPORTS_SSE2)
  if(CC_SUPPORTS_SSE2)
    add_definitions("-DOC_ENABLE_SSE2")
    message("-- Enabling SSE2 for AES")
  endif()

  check_c_compiler_flag_and_add(-maes CC_SUPPORTS_AES)
  if(CC_SUPPORTS_AES)
    add_definitions("-DOC_ENABLE_AESNI")
    message("-- Enabling AES_NI")
  else()
    add_definitions("-DOC_ENABLE_PORTABLE_AES")
  endif()
endif()

add_subdirectory(util)

find_package(helib 2.2.0 QUIET)
find_package(SEAL 3.7.3 QUIET)

if (NOT helib_FOUND OR NOT SEAL_FOUND)
    # prep external libraries
    add_subdirectory(thirdparty)
endif()

# Import HElib
find_package(helib 2.2.0 REQUIRED
    # Optionaly providing a path so this can be built without installing HElib
    PATHS ${symhe_SOURCE_DIR}/thirdparty/HElib/install/share/cmake/helib
)

# Import Microsoft SEAL
find_package(SEAL 3.7.3 REQUIRED
    # Optionaly providing a path so this can be built without installing SEAL
    PATHS ${symhe_SOURCE_DIR}/thirdparty/SEAL/build/cmake
)

# Import TFHE
set(TFHE_PREFIX "${CMAKE_SOURCE_DIR}/thirdparty/tfhe/installed")
set(TFHE_INCLUDE_DIR "${TFHE_PREFIX}/include")
# choose lib:
# set(TFHE_LIB "${TFHE_PREFIX}/lib/libtfhe-fftw.so")
# set(TFHE_LIB "${TFHE_PREFIX}/lib/libtfhe-nayuki-avx.so")
# set(TFHE_LIB "${TFHE_PREFIX}/lib/libtfhe-nayuki-portable.so")
# set(TFHE_LIB "${TFHE_PREFIX}/lib/libtfhe-spqlios-avx.so")
set(TFHE_LIB "${TFHE_PREFIX}/lib/libtfhe-spqlios-fma.so")

set(M4RI_PREFIX "${CMAKE_SOURCE_DIR}/thirdparty/m4ri/installed")
set(M4RI_INCLUDE_DIR "${M4RI_PREFIX}/include")
set(M4RI_LIB "${M4RI_PREFIX}/lib/libm4ri.so")

# collect all cipher implementations
add_subdirectory(ciphers)

# add tests
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
