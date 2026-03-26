cmake_minimum_required(VERSION 3.16)
project(sys_nse LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(sys_nse STATIC
  src/sys_nse.cpp
)

target_include_directories(sys_nse
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_executable(sys_nse_example
  examples/main.cpp
)

target_link_libraries(sys_nse_example PRIVATE sys_nse)

