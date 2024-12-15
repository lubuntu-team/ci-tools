#include "update_maintainer.h"
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

class MaintainerUpdateException : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

static std::optional<fs::path> find_control_file(const fs::path &debian_dir) {
    fs::path control_in = debian_dir / "control.in";
    fs::path control = debian_dir / "control";
    if (fs::exists(control_in)) return control_in;
    if (fs::exists(control)) return control;
    return std::nullopt;
}

static fs::path find_changelog_file(const fs::path &debian_dir) {
    fs::path changelog = debian_dir / "changelog";
    if (!fs::exists(changelog)) {
        throw MaintainerUpdateException("No changelog file found");
    }
    return changelog;
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

static std::string get_distribution(const fs::path &changelog_file) {
    // parse first line of changelog: "package (version) dist; urgency=..."
    // dist is the token after ')'
    std::ifstream f(changelog_file);
    if(!f) throw MaintainerUpdateException("Unable to open changelog.");
    std::string first_line;
    std::getline(f, first_line);
    // Format: "pkg (ver) dist; urgency=..."
    // find ') '
    size_t pos = first_line.find(')');
    if(pos == std::string::npos) throw MaintainerUpdateException("Invalid changelog format");
    // after ') ', next token is distribution until space
    // skip ')'
    pos++;
    while(pos < first_line.size() && std::isspace((unsigned char)first_line[pos])) pos++;
    // now read until space or ';'
    size_t start = pos;
    while(pos < first_line.size() && !std::isspace((unsigned char)first_line[pos]) && first_line[pos] != ';') pos++;
    std::string dist = first_line.substr(start, pos - start);
    // remove -proposed-updates etc
    size_t dashpos = dist.find('-');
    if (dashpos != std::string::npos) {
        dist = dist.substr(0, dashpos);
    }
    return dist;
}

static std::string read_file(const fs::path &p) {
    std::ifstream f(p);
    if(!f) throw MaintainerUpdateException("Cannot read file: " + p.string());
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static void write_file(const fs::path &p, const std::string &content) {
    std::ofstream f(p);
    if(!f) throw MaintainerUpdateException("Cannot write file: " + p.string());
    f << content;
}

static std::optional<std::string> get_field(const std::string &content, const std::string &field_regex) {
    std::regex r(field_regex, std::regex_constants::multiline);
    std::smatch m;
    if(std::regex_search(content, m, r)) {
        return m[1].str();
    }
    return std::nullopt;
}

static std::string set_field(const std::string &content, const std::string &field_regex, const std::string &new_line) {
    std::regex r(field_regex, std::regex_constants::multiline);
    return std::regex_replace(content, r, new_line);
}

static void update_maintainer_file(const fs::path &control_file, const std::string &distribution, bool verbose) {
    std::string c = read_file(control_file);

    auto original_maintainer = get_field(c, "^Maintainer:\\s?(.*)$");
    if(!original_maintainer) {
        throw MaintainerUpdateException("No Maintainer field found");
    }

    std::string om = *original_maintainer;
    std::string om_lower = om;
    for (auto &ch : om_lower) ch = (char)std::tolower((unsigned char)ch);

    // Check previous ubuntu maintainers
    for (auto &pm : PREVIOUS_UBUNTU_MAINTAINERS) {
        std::string pm_lower = pm;
        for (auto &ch: pm_lower) ch=(char)std::tolower((unsigned char)ch);
        if(pm_lower == om_lower) {
            if(verbose) {
                std::cout<<"The old maintainer was: "<<om<<"\n";
                std::cout<<"Resetting as: "<<UBUNTU_MAINTAINER<<"\n";
            }
            // just set maintainer
            std::regex maint_re("^Maintainer:\\s?.*$", std::regex_constants::multiline);
            c = std::regex_replace(c, maint_re, "Maintainer: " + std::string(UBUNTU_MAINTAINER));
            write_file(control_file, c);
            return;
        }
    }

    // If ends with ubuntu.com, do nothing
    {
        std::string lower_om = om_lower;
        if (lower_om.rfind("ubuntu.com>", lower_om.size()-11) != std::string::npos) {
            if(verbose) {
                std::cout<<"The Maintainer email is ubuntu.com address. Doing nothing.\n";
            }
            return;
        }
    }

    // Debian distributions: stable, testing, unstable, experimental
    if(distribution=="stable"||distribution=="testing"||distribution=="unstable"||distribution=="experimental") {
        if(verbose) {
            std::cout<<"The package targets Debian. Doing nothing.\n";
        }
        return;
    }

    // set XSBC-Original-Maintainer if needed
    auto orig_field = get_field(c, "^(?:[XSBC]*-)?Original-Maintainer:\\s?(.*)$");
    if(orig_field && verbose) {
        std::cout<<"Overwriting original maintainer: "<< *orig_field <<"\n";
    }

    if(verbose) {
        std::cout<<"The original maintainer is: "<< om <<"\n";
        std::cout<<"Resetting as: "<<UBUNTU_MAINTAINER<<"\n";
    }

    // set original maint
    if(orig_field) {
        // pattern to replace original maint
        std::regex orig_re("^(?:[XSBC]*-)?Original-Maintainer:.*$", std::regex_constants::multiline);
        c = std::regex_replace(c, orig_re, "XSBC-Original-Maintainer: " + om);
    } else {
        // insert after Maintainer line
        std::regex maint_re("^(Maintainer:.*)$", std::regex_constants::multiline);
        c = std::regex_replace(c, maint_re, "$1\nXSBC-Original-Maintainer: " + om);
    }

    // now set maint
    {
        std::regex maint_re("^Maintainer:\\s?.*$", std::regex_constants::multiline);
        c = std::regex_replace(c, maint_re, "Maintainer: " + std::string(UBUNTU_MAINTAINER));
    }

    write_file(control_file, c);
}

void update_maintainer(const std::string &debian_directory, bool verbose) {
    fs::path debian_dir(debian_directory);
    auto control_file = find_control_file(debian_dir);
    if(!control_file) {
        throw MaintainerUpdateException("No control file found");
    }
    fs::path changelog = find_changelog_file(debian_dir);
    if(xsbc_managed_by_rules(debian_dir)) {
        if(verbose) {
            std::cout<<"XSBC-Original is managed by rules. Doing nothing.\n";
        }
        return;
    }

    std::string distribution = get_distribution(changelog);

    update_maintainer_file(*control_file, distribution, verbose);
}
