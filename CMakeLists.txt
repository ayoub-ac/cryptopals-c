cmake_minimum_required(VERSION 3.14)
project(cryptopals C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 14)

# download GTest automatically
include(FetchContent)
FetchContent_Declare(googletest URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip)
FetchContent_MakeAvailable(googletest)

# compile all .c files in src/ into a library
file(GLOB CHALLENGE_SOURCES src/*.c)
add_library(challenges ${CHALLENGE_SOURCES})
target_include_directories(challenges PUBLIC include)

# find all test files and create one executable per test
enable_testing()
include(GoogleTest)

file(GLOB TEST_SOURCES tests/test_ch*.cpp)
foreach(test_file ${TEST_SOURCES})
    get_filename_component(test_name ${test_file} NAME_WE)
    add_executable(${test_name} ${test_file})
    target_link_libraries(${test_name} challenges GTest::gtest_main)
    gtest_discover_tests(${test_name})
endforeach()
