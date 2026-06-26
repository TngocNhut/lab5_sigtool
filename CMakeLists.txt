cmake_minimum_required(VERSION 3.20)

project(lab5_sigtool
    VERSION 1.0.0
    DESCRIPTION "Lab 5 - Classical Digital Signatures: ECDSA and RSA-PSS"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

add_executable(sigtool
    src/main.cpp
    src/file_utils.cpp
    src/signature_tool.cpp
)

target_include_directories(sigtool
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(sigtool
    PRIVATE
        OpenSSL::Crypto
)

if (MSVC)
    target_compile_options(sigtool PRIVATE /W4)
else()
    target_compile_options(sigtool PRIVATE -Wall -Wextra -Wpedantic)
endif()

enable_testing()
