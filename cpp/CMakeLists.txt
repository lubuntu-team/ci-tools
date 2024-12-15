cmake_minimum_required(VERSION 3.21)
project(lubuntuci CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Specify output directories
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Find required packages
find_package(yaml-cpp REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBGIT2 REQUIRED IMPORTED_TARGET libgit2)
find_package(CURL REQUIRED)
find_package(ZLIB REQUIRED)

# Locate Launchpadlib
# Assuming Launchpadlib is installed in /srv/lubuntu-ci/repos/ci-tools/lib/
# Adjust the path if necessary
find_library(LAUNCHPADLIB_LIB NAMES launchpadlib liblaunchpad REQUIRED PATHS /srv/lubuntu-ci/repos/ci-tools/lib/ NO_DEFAULT_PATH)
if(NOT LAUNCHPADLIB_LIB)
    message(FATAL_ERROR "launchpadlib not found")
endif()

# Include directories for Launchpadlib
include_directories(/srv/lubuntu-ci/repos/ci-tools/include/launchpadlib-cpp)

# Create the shared library liblubuntuci.so
add_library(lubuntuci SHARED common.cpp utilities.cpp)
target_include_directories(lubuntuci PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(lubuntuci PRIVATE yaml-cpp)

# Ensure liblubuntuci has proper RPATH
set_target_properties(lubuntuci PROPERTIES
    BUILD_WITH_INSTALL_RPATH TRUE
    INSTALL_RPATH "$ORIGIN/lib"
)

# build-packages executable
add_executable(build-packages build-packages.cpp)
target_link_libraries(build-packages PRIVATE lubuntuci PkgConfig::LIBGIT2 yaml-cpp ${LIBGIT2_LIBRARIES} ${YAML_CPP_LIBRARIES} ${LAUNCHPADLIB_LIB})

# fetch-indexes executable
add_executable(fetch-indexes fetch-indexes.cpp utilities.cpp)
target_include_directories(fetch-indexes PRIVATE ${CURL_INCLUDE_DIRS} ${ZLIB_INCLUDE_DIRS} /srv/lubuntu-ci/repos/ci-tools/include/launchpadlib-cpp)
target_link_libraries(fetch-indexes PRIVATE lubuntuci CURL::libcurl ZLIB::ZLIB yaml-cpp ${LAUNCHPADLIB_LIB})

# update-maintainer executable
add_executable(update-maintainer update-maintainer.cpp)
# Link only necessary libraries, avoiding liblubuntuci
target_include_directories(update-maintainer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} /srv/lubuntu-ci/repos/ci-tools/include/launchpadlib-cpp)
target_link_libraries(update-maintainer PRIVATE yaml-cpp ${LAUNCHPADLIB_LIB})

# Ensure executables have proper RPATH
set_target_properties(build-packages fetch-indexes update-maintainer PROPERTIES
    BUILD_WITH_INSTALL_RPATH TRUE
    INSTALL_RPATH "$ORIGIN/lib"
)

# Install targets
install(TARGETS lubuntuci
    LIBRARY DESTINATION lib
)

install(TARGETS build-packages fetch-indexes update-maintainer
    RUNTIME DESTINATION bin
)

# Install headers
install(FILES common.h update-maintainer.h utilities.h
    DESTINATION include/lubuntuci
)
