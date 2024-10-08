cmake_minimum_required(VERSION 3.13)



###############################################################################
## LIBRARY-PROJECT
## name and version
###############################################################################
project(RF62X-Core VERSION 2.27.2 LANGUAGES C)



###############################################################################
## SETTINGS
## basic project settings before use
###############################################################################
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_C_STANDARD 99)
# Enabling export of all symbols to create a dynamic library
set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
# creating output directory architecture in accordance with GNU guidelines
set(BINARY_DIR "${CMAKE_BINARY_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${BINARY_DIR}/lib")
file (GLOB_RECURSE IN_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.h.in)
configure_file(${IN_FILES} ${CMAKE_CURRENT_SOURCE_DIR}/rf62X_core_version.h)



###############################################################################
## TARGET
## create target and add include path
###############################################################################
# create glob files for *.h, *.c
file(GLOB_RECURSE C_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.c)
file(GLOB_RECURSE H_FILES ${CMAKE_CURRENT_SOURCE_DIR}/*.h)
# concatenate the results (glob files) to variable
set (SOURCES ${C_FILES} ${H_FILES})
# create lib from src
if (NOT TARGET ${PROJECT_NAME})
    add_library(${PROJECT_NAME} STATIC ${SOURCES})
endif()
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/)



###############################################################################
## LINK LIBRARIES
## linking all dependencies
###############################################################################
find_package (Threads)
target_link_libraries (${PROJECT_NAME} ${CMAKE_THREAD_LIBS_INIT})

target_link_libraries(${PROJECT_NAME} RF627-Protocol)
target_link_libraries(${PROJECT_NAME} RF62X-Protocol)

target_link_libraries(${PROJECT_NAME} platform_methods)
target_link_libraries(${PROJECT_NAME} endian_conv)
target_link_libraries(${PROJECT_NAME} custom_vector)
target_link_libraries(${PROJECT_NAME} custom_string)
target_link_libraries(${PROJECT_NAME} sandbox)

if (MSVC)
    target_link_libraries(${PROJECT_NAME} libpthreads4w)
    target_link_libraries(${PROJECT_NAME} getopt)
endif()

