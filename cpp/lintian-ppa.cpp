#include "common.h"
#include "ci_logic.h"
#include <yaml-cpp/yaml.h>
#include <filesystem>
#include <iostream>
#include <vector>
#include <string>

int main(int argc, char** argv) {
    if (argc<2) {
        std::cerr << "Usage: lintian-ppa <some.changes> [--verbose]\n";
        return 1;
    }
    for (int i=1; i<argc; i++) {
        std::string arg = argv[i];
        if (arg=="--verbose" || arg=="-v") {
            verbose = true;
        }
    }
    std::string changes_path = argv[1];

    try {
        if (!run_command({"lintian", "-EvIL", "+pedantic", changes_path}, std::nullopt, false)) {
            return 1;
        }
    } catch(...) {
        log_error("Lintian reported some issues with " + changes_path);
    }

    return 0;
}
