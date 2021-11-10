cmake_minimum_required(VERSION 2.8)

project(s5p)

set(CMAKE_MODULE_PATH "${${PROJECT_NAME}_SOURCE_DIR}/cmake/CMakeModules;${CMAKE_MODULE_PATH}")
set(CMAKE_PREFIX_PATH "${CMAKE_PREFIX_PATH}")

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /EHa /Od /bigobj")
#/EHa          vc编译器在release版默认是同步异常，做了优化，只会检查代码中有显式throw的异常，不能捕获非法内存访问、除零等结构化异常，修改release的编译选项，加个/EHa就好了
#/Od           禁止优化
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
endif()

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
message(STATUS "CMAKE_CXX_FLAGS                   =${CMAKE_CXX_FLAGS}")

#############Boost
find_package(Boost COMPONENTS locale program_options system)

message(STATUS "Boost_INCLUDE_DIRS                      =${Boost_INCLUDE_DIRS}")
message(STATUS "Boost_LIBRARIES                         =${Boost_LIBRARIES}")

if(${Boost_FOUND})
    set(INCLUDES ${INCLUDES} ${Boost_INCLUDE_DIRS})
    set(LINKLIBRARIES ${LINKLIBRARIES} ${Boost_LIBRARIES})
endif()

message(STATUS "INCLUDES                          =${INCLUDES}")
message(STATUS "LINKLIBRARIES                     =${LINKLIBRARIES}")

add_executable(${PROJECT_NAME}
    server.h
    server.cpp
    log.h
    encode.h
    session_local_proxy.h
    session_local_proxy.cpp
    session_remote_proxy.h
    session_remote_proxy.cpp
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
