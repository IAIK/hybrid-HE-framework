cmake_minimum_required(VERSION 3.4.1)
project(Keccak C)

set(KECCAK_SRCS
  KeccakSpongeWidth1600.c
  KeccakHash.c
  )




if(MSVC)
set(DEFAULT_USE_AVX2 OFF)
else()
set(DEFAULT_USE_AVX2 ON)
endif()
set(USE_AVX2 ${DEFAULT_USE_AVX2} CACHE BOOL "USE AVX2 version.")


if (USE_AVX2)
  set(KECCAK_SRCS ${KECCAK_SRCS}
    avx2/KeccakP-1600-AVX2.s
    )
  set_property(SOURCE avx2/KeccakP-1600-AVX2.s PROPERTY LANGUAGE C)
else ()
  set(KECCAK_SRCS ${KECCAK_SRCS}
    opt64/KeccakP-1600-opt64.c
    )
endif ()

add_library(keccak STATIC ${KECCAK_SRCS})
target_include_directories(keccak PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
if (USE_AVX2)
  target_include_directories(keccak PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/avx2/")
else ()
  target_include_directories(keccak PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/opt64/")
endif ()

