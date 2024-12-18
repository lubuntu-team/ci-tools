cmake_minimum_required(VERSION 3.21)
project(lubuntuci CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

find_package(yaml-cpp REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBGIT2 REQUIRED IMPORTED_TARGET libgit2)
find_package(CURL REQUIRED)
find_library(UUID_LIB uuid)
find_package(ZLIB REQUIRED)

pkg_check_modules(LIBARCHIVE REQUIRED libarchive)
include_directories(${LIBARCHIVE_INCLUDE_DIRS})
link_directories(${LIBARCHIVE_LIBRARY_DIRS})
add_definitions(${LIBARCHIVE_CFLAGS_OTHER})

include_directories(/srv/lubuntu-ci/repos/ci-tools/include/launchpadlib-cpp)

add_library(lubuntuci SHARED common.cpp utilities.cpp)
target_include_directories(lubuntuci PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${LIBARCHIVE_INCLUDE_DIRS})
target_link_libraries(lubuntuci PUBLIC yaml-cpp::yaml-cpp PRIVATE CURL::libcurl ${LIBARCHIVE_LIBRARIES} /srv/lubuntu-ci/repos/ci-tools/lib/liblaunchpad.so)

add_library(update_maintainer_lib STATIC update-maintainer-lib.cpp)
target_include_directories(update_maintainer_lib PRIVATE /srv/lubuntu-ci/repos/ci-tools/include/launchpadlib-cpp)
target_link_libraries(update_maintainer_lib PRIVATE lubuntuci yaml-cpp::yaml-cpp CURL::libcurl)

add_executable(update-maintainer update-maintainer.cpp)
target_link_libraries(update-maintainer PRIVATE update_maintainer_lib)

add_executable(build-packages build-packages.cpp)
target_include_directories(build-packages PRIVATE /srv/lubuntu-ci/repos/ci-tools/include/launchpadlib-cpp)
target_link_libraries(build-packages PRIVATE lubuntuci PkgConfig::LIBGIT2 update_maintainer_lib yaml-cpp::yaml-cpp)

add_executable(fetch-indexes fetch-indexes.cpp utilities.cpp)
target_include_directories(fetch-indexes PRIVATE /srv/lubuntu-ci/repos/ci-tools/include/launchpadlib-cpp)
target_link_libraries(fetch-indexes PRIVATE lubuntuci CURL::libcurl yaml-cpp::yaml-cpp ZLIB::ZLIB /srv/lubuntu-ci/repos/ci-tools/lib/liblaunchpad.so)

add_executable(lintian-ppa lintian-ppa.cpp)
target_include_directories(lintian-ppa PRIVATE /srv/lubuntu-ci/repos/ci-tools/include/launchpadlib-cpp)
target_link_libraries(lintian-ppa PRIVATE lubuntuci ${UUID_LIB} /srv/lubuntu-ci/repos/ci-tools/lib/liblaunchpad.so)

set_target_properties(lubuntuci build-packages fetch-indexes update-maintainer lintian-ppa PROPERTIES
    BUILD_WITH_INSTALL_RPATH TRUE
    INSTALL_RPATH "$ORIGIN/lib"
)

install(TARGETS lubuntuci
    LIBRARY DESTINATION lib
)

install(TARGETS build-packages fetch-indexes update-maintainer lintian-ppa
    RUNTIME DESTINATION .
)

install(FILES common.h update-maintainer-lib.h utilities.h
    DESTINATION include/lubuntuci
)
