cmake_minimum_required(VERSION 3.21)
project(build-packages CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(yaml-cpp REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBGIT2 REQUIRED IMPORTED_TARGET libgit2)

add_library(common SHARED common.cpp)
target_link_libraries(common yaml-cpp)

add_library(update_maintainer SHARED update_maintainer.cpp)

add_executable(build-packages main.cpp)
target_link_libraries(build-packages common update_maintainer PkgConfig::LIBGIT2 yaml-cpp)

set(CMAKE_INSTALL_RPATH "$ORIGIN/lib")
set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)

install(TARGETS common LIBRARY DESTINATION lib)
install(TARGETS update_maintainer LIBRARY DESTINATION lib)
install(TARGETS build-packages RUNTIME DESTINATION .)
