// Copyright (C) 2024-2025 Simon Quigley <tsimonq2@ubuntu.com>
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

#include "update-maintainer-lib.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <stdexcept>
#include <string>
#include <optional>

namespace fs = std::filesystem;

static const char* PREVIOUS_UBUNTU_MAINTAINERS[] = {
    "ubuntu core developers <ubuntu-devel@lists.ubuntu.com>",
    "ubuntu core developers <ubuntu-devel-discuss@lists.ubuntu.com>",
    "ubuntu motu developers <ubuntu-motu@lists.ubuntu.com>"
};
static const char* UBUNTU_MAINTAINER = "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>";

static fs::path find_control_file(const fs::path &debian_dir) {
    fs::path control_in = debian_dir / "control.in";
    fs::path control = debian_dir / "control";
    if (fs::exists(control_in)) {
        return control_in;
    }
    if (fs::exists(control)) {
        return control;
    }
    throw std::runtime_error("No control file found in " + debian_dir.string());
}

static bool xsbc_managed_by_rules(const fs::path &debian_dir) {
    fs::path rules = debian_dir / "rules";
    if (!fs::exists(rules)) return false;
    std::ifstream rf(rules);
    std::string line;
    while (std::getline(rf, line)) {
        if (line.find("XSBC-Original-") != std::string::npos) {
            return true;
        }
    }
    return false;
}

static std::string read_file(const fs::path &p) {
    std::ifstream f(p);
    if(!f) throw std::runtime_error("Cannot read file: " + p.string());
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static void write_file(const fs::path &p, const std::string &content) {
    std::ofstream f(p);
    if(!f) throw std::runtime_error("Cannot write file: " + p.string());
    f << content;
}

static void update_maintainer_file(const fs::path &control_file, bool verbose) {
    std::string c = read_file(control_file);

    // Helper lambda to find a field
    auto find_field = [&](const std::string &field) -> std::optional<std::string> {
        std::regex r("^" + field + ":\\s?(.*)$", std::regex_constants::icase | std::regex_constants::multiline);
        std::smatch m;
        if(std::regex_search(c, m, r)) {
            return m[1].str();
        }
        return std::nullopt;
    };

    // Helper lambda to replace a field line
    auto replace_field = [&](const std::string &field, const std::string &val) {
        std::regex r("^" + field + ":\\s?.*$", std::regex_constants::icase | std::regex_constants::multiline);
        c = std::regex_replace(c, r, field + ": " + val);
    };

    auto original_maint = find_field("Maintainer");
    if(!original_maint) {
        throw std::runtime_error("No Maintainer field found in " + control_file.string());
    }

    std::string om_lower = *original_maint;
    for (auto &ch : om_lower) {
        ch = (char)std::tolower((unsigned char)ch);
    }

    // If the original maintainer is a known Ubuntu style, just unify
    for (auto &pm : PREVIOUS_UBUNTU_MAINTAINERS) {
        std::string pm_lower = pm;
        for (auto &ch: pm_lower) {
            ch = (char)std::tolower((unsigned char)ch);
        }
        if (pm_lower == om_lower) {
            if(verbose) {
                std::cout << "[update-maintainer] Old maintainer was: " << *original_maint << "\n"
                          << "Resetting as: " << UBUNTU_MAINTAINER << std::endl;
            }
            replace_field("Maintainer", UBUNTU_MAINTAINER);
            write_file(control_file, c);
            return;
        }
    }

    // If ends with ubuntu.com, do nothing
    // e.g. ... <someone@ubuntu.com>
    if (om_lower.size() >= 11 &&
        om_lower.rfind("ubuntu.com>", om_lower.size()-11) != std::string::npos)
    {
        if(verbose) {
            std::cout << "[update-maintainer] Maintainer is an @ubuntu.com address. Doing nothing.\n";
        }
        return;
    }

    // If there's no XSBC-Original, insert it after Maintainer
    auto check_xsbc = find_field("XSBC-Original-Maintainer");
    if(!check_xsbc) {
        std::regex maint_re("^(Maintainer:.*)$",
                            std::regex_constants::multiline | std::regex_constants::icase);
        if(std::regex_search(c, maint_re)) {
            c = std::regex_replace(c, maint_re,
                                   "$1\nXSBC-Original-Maintainer: " + *original_maint);
        }
    } else {
        if(verbose) {
            std::cout << "[update-maintainer] Overwriting XSBC-Original-Maintainer with: " << *original_maint << "\n";
        }
        replace_field("XSBC-Original-Maintainer", *original_maint);
    }

    if(verbose) {
        std::cout << "[update-maintainer] Setting Maintainer to: " << UBUNTU_MAINTAINER << std::endl;
    }
    replace_field("Maintainer", UBUNTU_MAINTAINER);
    write_file(control_file, c);
}

void update_maintainer(const std::string &debian_directory, bool verbose) {
    fs::path debian_dir(debian_directory);
    fs::path control_file = find_control_file(debian_dir);
    if(xsbc_managed_by_rules(debian_dir)) {
        if(verbose) {
            std::cout << "[update-maintainer] XSBC is managed by debian/rules, skipping.\n";
        }
        return;
    }

    update_maintainer_file(control_file, verbose);
}
