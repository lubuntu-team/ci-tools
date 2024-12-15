cmake_minimum_required(VERSION 3.10)
project(fetch-indexes)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(CURL REQUIRED)
find_package(ZLIB REQUIRED)
find_package(YAML-CPP REQUIRED)
include_directories(${CURL_INCLUDE_DIRS})
include_directories(${ZLIB_INCLUDE_DIRS})
include_directories(${YAML_CPP_INCLUDE_DIR})
include_directories(/srv/lubuntu-ci/repos/ci-tools/include/launchpadlib-cpp)

add_executable(fetch-indexes main.cpp utilities.cpp)

target_link_libraries(fetch-indexes ${CURL_LIBRARIES} ${ZLIB_LIBRARIES} yaml-cpp /srv/lubuntu-ci/repos/ci-tools/lib/liblaunchpad.so)
