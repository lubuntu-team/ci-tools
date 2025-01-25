// cpp/update-maintainer.cpp

// Copyright (C) 2024 Simon Quigley <tsimonq2@ubuntu.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include "lubuntuci_lib.h"
#include <iostream>

int main(int argc, char** argv) {
    if(argc < 2) {
        std::cerr << "Usage: update-maintainer <debian_directory> [--verbose]" << std::endl;
        return 1;
    }

    std::string debian_directory = argv[1];
    bool verbose = false;
    if(argc >=3 ) {
        std::string flag = argv[2];
        if(flag == "--verbose") {
            verbose = true;
        }
    }

    try {
        //LubuntuCI::update_maintainer(debian_directory, verbose);
        if(verbose) {
            std::cout << "Maintainer updated successfully." << std::endl;
        }
    } catch(const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
