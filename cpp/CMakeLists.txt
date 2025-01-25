cmake_minimum_required(VERSION 3.16)
project(lubuntu_ci_all CXX)

set(CMAKE_AUTOMOC ON)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)

#
# Allow the user to override LAUNCHPAD_CPP_INCLUDE_DIR/LAUNCHPAD_CPP_LIBRARY
#
if (NOT DEFINED LAUNCHPAD_CPP_INCLUDE_DIR)
    set(LAUNCHPAD_CPP_INCLUDE_DIR "/srv/lubuntu-ci/repos/ci-tools/include/launchpadlib-cpp")
endif()
if (NOT DEFINED LAUNCHPAD_CPP_LIBRARY)
    set(LAUNCHPAD_CPP_LIBRARY "/srv/lubuntu-ci/repos/ci-tools/lib/liblaunchpad.so")
endif()

find_package(Qt6 REQUIRED COMPONENTS Core HttpServer Sql)
find_package(PkgConfig REQUIRED)
find_package(yaml-cpp REQUIRED)
pkg_check_modules(LIBARCHIVE REQUIRED libarchive)
pkg_check_modules(LIBGIT2 REQUIRED libgit2)
find_package(ZLIB REQUIRED)
find_package(CURL REQUIRED)
set(UUID_LIB "uuid")

#
# 1. The main library: lubuntuci_lib
#
add_library(lubuntuci_lib SHARED
    common.cpp
    utilities.cpp
    ci_logic.cpp
    ci_database_objs.cpp
    lubuntuci_lib.cpp
    task_queue.cpp
    template_renderer.cpp
    web_server.cpp
    sources_parser.cpp
    naive_bayes_classifier.cpp
    db_common.cpp
)

target_include_directories(lubuntuci_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    "${LAUNCHPAD_CPP_INCLUDE_DIR}"
)

target_link_libraries(lubuntuci_lib
    Qt6::Core
    Qt6::HttpServer
    Qt6::Sql
    yaml-cpp
    ${LIBARCHIVE_LIBRARIES}
    ${LIBGIT2_LIBRARIES}
    "${LAUNCHPAD_CPP_LIBRARY}"
    ZLIB::ZLIB
    CURL::libcurl
    ${UUID_LIB}
)

#
# 2. The update-maintainer-lib library
#
add_library(update_maintainer_lib STATIC
    update-maintainer-lib.cpp
)
target_include_directories(update_maintainer_lib PRIVATE
    "${LAUNCHPAD_CPP_INCLUDE_DIR}"
)
target_link_libraries(update_maintainer_lib
    lubuntuci_lib
    yaml-cpp
    CURL::libcurl
    ${LIBARCHIVE_LIBRARIES}
    ${LIBGIT2_LIBRARIES}
    ZLIB::ZLIB
    "${LAUNCHPAD_CPP_LIBRARY}"
    ${UUID_LIB}
)

#
# 3. Build each executable
#

add_executable(update-maintainer update-maintainer.cpp)
target_link_libraries(update-maintainer
    lubuntuci_lib
    update_maintainer_lib
    yaml-cpp
    ${LIBARCHIVE_LIBRARIES}
    ${LIBGIT2_LIBRARIES}
    ZLIB::ZLIB
    CURL::libcurl
    "${LAUNCHPAD_CPP_LIBRARY}"
    ${UUID_LIB}
)

add_executable(lintian-ppa lintian-ppa.cpp)
target_link_libraries(lintian-ppa
    lubuntuci_lib
    yaml-cpp
    ${LIBARCHIVE_LIBRARIES}
    ${LIBGIT2_LIBRARIES}
    "${LAUNCHPAD_CPP_LIBRARY}"
    ZLIB::ZLIB
    CURL::libcurl
    ${UUID_LIB}
)

add_executable(fetch-indexes fetch-indexes.cpp)
target_link_libraries(fetch-indexes
    lubuntuci_lib
    yaml-cpp
    ${LIBARCHIVE_LIBRARIES}
    ${LIBGIT2_LIBRARIES}
    "${LAUNCHPAD_CPP_LIBRARY}"
    ZLIB::ZLIB
    CURL::libcurl
    ${UUID_LIB}
)

add_executable(web_ui main.cpp)
target_link_libraries(web_ui
    lubuntuci_lib
    yaml-cpp
    ${LIBARCHIVE_LIBRARIES}
    ${LIBGIT2_LIBRARIES}
    ZLIB::ZLIB
    CURL::libcurl
    "${LAUNCHPAD_CPP_LIBRARY}"
    ${UUID_LIB}
)

install(TARGETS lubuntuci_lib
    LIBRARY DESTINATION lib
)
install(TARGETS web_ui fetch-indexes update-maintainer lintian-ppa
    RUNTIME DESTINATION .
)
