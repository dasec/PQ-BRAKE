cmake_minimum_required(VERSION 3.10)
set(OQS_CPP_VERSION_NUM 0.7.2)
set(OQS_CPP_VERSION_STR "${OQS_CPP_VERSION_NUM}")
project(thesis_impl)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# liboqs-cpp version number
add_definitions(-DOQS_CPP_VERSION="${OQS_CPP_VERSION_STR}")

# Path to liboqs include and lib, modify as needed
if (NOT WIN32)
    set(LIBOQS_INCLUDE_DIR "/usr/local/include" CACHE PATH
            "Path to liboqs include directory")
    set(LIBOQS_LIB_DIR "/usr/local/lib" CACHE PATH
            "Path to liboqs lib directory")
else ()
    # Increase the stack size to 8MB on Windows
    if (MSVC)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /STACK:8388608")
    elseif (${CMAKE_CXX_COMPILER_ID} MATCHES "Clang" OR ${CMAKE_CXX_COMPILER_ID}
            STREQUAL "GNU")
        set(CMAKE_EXE_LINKER_FLAGS
                "${CMAKE_EXE_LINKER_FLAGS} -Wl,--stack,8388608")
    endif ()
    set(LIBOQS_INCLUDE_DIR "" CACHE PATH "Path to liboqs include directory")
    set(LIBOQS_LIB_DIR "" CACHE PATH "Path to liboqs lib directory")
endif ()

if (LIBOQS_INCLUDE_DIR STREQUAL "")
    message(FATAL_ERROR "Please specify the path to the liboqs include directory\
    by setting the LIBOQS_INCLUDE_DIR cmake flag, i.e.
    cmake -DLIBOQS_INCLUDE_DIR=/path/to/liboqs/include")
elseif (NOT IS_DIRECTORY ${LIBOQS_INCLUDE_DIR})
    message(FATAL_ERROR "Invalid path to the liboqs include directory")
endif ()

if (LIBOQS_LIB_DIR STREQUAL "")
    message(FATAL_ERROR "Please specify the path to the liboqs lib directory\
    by setting the LIBOQS_LIB_DIR cmake flag, i.e.
    cmake -DLIBOQS_LIB_DIR=/path/to/liboqs/include")
elseif (NOT IS_DIRECTORY ${LIBOQS_LIB_DIR})
    message(FATAL_ERROR "Invalid path to the liboqs lib directory")
endif ()

include_directories("include")
include_directories(SYSTEM "${LIBOQS_INCLUDE_DIR}")
link_directories("${LIBOQS_LIB_DIR}")

# Default build type
if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING
            "Choose the type of build, options are: \
         None Debug Release MinSizeRel RelWithDebInfo."
            FORCE)
endif ()

# Enable all warnings for GNU gcc and Clang/AppleClang
if (${CMAKE_CXX_COMPILER_ID} MATCHES "Clang" OR ${CMAKE_CXX_COMPILER_ID}
        STREQUAL "GNU")
    set(-g -02 CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pedantic -Wall -Wextra -Weffc++ -pthread -march=native")
endif ()

include_directories("/usr/include/NTL")
add_library(CoreFiles ./operations/Crypto.cpp ./operations/Helpers.cpp ./participants/Client.cpp participants/Evaluator.cpp fuzzyVault/FJFXFingerprint.cpp fuzzyVault/FJFXFingerprint.hpp fuzzyVault/Thimble.cpp fuzzyVault/Thimble.hpp)
add_executable(01_test_KEM tests/01_test_KEM.cpp)
add_executable(02_test_OPRF tests/02_test_OPRF.cpp)
add_executable(03_test_PQBRAKE tests/03_test_PQBRAKE.cpp)
target_link_libraries(01_test_KEM CoreFiles oqs ntl gmp crypto)
target_link_libraries(02_test_OPRF CoreFiles oqs ntl gmp crypto)
target_link_libraries(03_test_PQBRAKE CoreFiles oqs ntl gmp crypto FJFX FRFXLL thimble)


