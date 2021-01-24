cmake_minimum_required(VERSION 2.8)

if(UNIX)
#    set(BOOST_INCLUDEDIR "/usr/include/boost169")
#    set(BOOST_LIBRARYDIR "/usr/lib64/boost169")
else()
    set(VCPKG_CMAKE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")
    set(VCPKG_TARGET_TRIPLET "x64-windows")
    set(CMAKE_TOOLCHAIN_FILE ${VCPKG_CMAKE})
endif()

project(s5p)

if(UNIX)
    set(CMAKE_MODULE_PATH "${${PROJECT_NAME}_SOURCE_DIR}/cmake/CMakeModules;${CMAKE_MODULE_PATH}")
    set(CMAKE_PREFIX_PATH "${CMAKE_PREFIX_PATH}")
else()
    set(CMAKE_MODULE_PATH "${${PROJECT_NAME}_SOURCE_DIR}/cmake/CMakeModules;$ENV{VCPKG_ROOT};${CMAKE_MODULE_PATH}")
    set(CMAKE_PREFIX_PATH "$ENV{VCPKG_ROOT};${CMAKE_PREFIX_PATH}")
endif()

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(INCLUDES)
set(LINKLIBRARIES)

if(UNIX)
    set(LINKLIBRARIES ${LINKLIBRARIES} pthread)
else()
    set(LINKLIBRARIES ${LINKLIBRARIES} wsock32 ws2_32)
endif()

message(STATUS "CMAKE_TOOLCHAIN_FILE              =${CMAKE_TOOLCHAIN_FILE}")
message(STATUS "CMAKE_INSTALL_PREFIX              =${CMAKE_INSTALL_PREFIX}")
message(STATUS "CMAKE_MODULE_PATH                 =${CMAKE_MODULE_PATH}")
message(STATUS "CMAKE_PREFIX_PATH                 =${CMAKE_PREFIX_PATH}")
message(STATUS "CMAKE_BUILD_TYPE                  =${CMAKE_BUILD_TYPE}")

#############Boost
find_package(Boost COMPONENTS locale program_options system)
if(${Boost_FOUND})
    set(INCLUDES ${INCLUDES} ${Boost_INCLUDE_DIRS})
    set(LINKLIBRARIES ${LINKLIBRARIES} ${Boost_LIBRARIES})
endif()

message(STATUS "INCLUDES                          =${INCLUDES}")
message(STATUS "LINKLIBRARIES                     =${LINKLIBRARIES}")

add_executable(${PROJECT_NAME}
    s5p.h
    s5p.cpp
    main.cpp)

target_include_directories(${PROJECT_NAME} PRIVATE ${INCLUDES})

target_link_libraries(${PROJECT_NAME} ${LINKLIBRARIES})

if(MSVC)
    target_compile_options(${PROJECT_NAME} PUBLIC /source-charset:utf-8)
elseif(MINGW)
    #centos7无法识别，mingw-w64作为编译器时才可用
    target_compile_options(${PROJECT_NAME} PUBLIC -municode)
else()
endif()
