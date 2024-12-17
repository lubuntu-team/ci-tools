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

#include "common.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <chrono>
#include <regex>

namespace fs = std::filesystem;

static void log_info(const std::string &msg) {
    std::cout << "[INFO] " << msg << "\n";
}
static void log_error(const std::string &msg) {
    std::cerr << "[ERROR] " << msg << "\n";
}

std::string parse_version(const fs::path &changelog_path) {
    if (!fs::exists(changelog_path)) {
        throw std::runtime_error("Changelog not found: " + changelog_path.string());
    }
    std::ifstream f(changelog_path);
    if (!f) throw std::runtime_error("Unable to open changelog");
    std::string first_line;
    std::getline(f, first_line);
    f.close();

    size_t start = first_line.find('(');
    size_t end = first_line.find(')');
    if (start == std::string::npos || end == std::string::npos) {
        throw std::runtime_error("Invalid changelog format");
    }
    std::string version_match = first_line.substr(start+1, end - (start+1));

    std::string epoch;
    std::string upstream_version = version_match;
    if (auto pos = version_match.find(':'); pos != std::string::npos) {
        epoch = version_match.substr(0, pos);
        upstream_version = version_match.substr(pos+1);
    }
    if (auto pos = upstream_version.find('-'); pos != std::string::npos) {
        upstream_version = upstream_version.substr(0, pos);
    }

    std::regex git_regex("(\\+git[0-9]+)?(~[a-z]+)?$");
    upstream_version = std::regex_replace(upstream_version, git_regex, "");

    auto t = std::time(nullptr);
    std::tm tm = *std::gmtime(&t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y%m%d%H%M", &tm);
    std::string current_date = buf;

    std::string version;
    if (!epoch.empty()) {
        version = epoch + ":" + upstream_version + "+git" + current_date;
    } else {
        version = upstream_version + "+git" + current_date;
    }

    return version;
}

void run_command(const std::vector<std::string> &cmd, const std::optional<fs::path> &cwd, bool show_output) {
    std::string full_cmd;
    for (const auto &c : cmd) {
        full_cmd += c + " ";
    }
    if (cwd) {
        full_cmd = "cd " + cwd->string() + " && " + full_cmd;
    }
    log_info("Executing: " + full_cmd);
    int ret = std::system(full_cmd.c_str());
    if (ret != 0) {
        log_error("Command failed: " + full_cmd);
        throw std::runtime_error("Command failed");
    }
    if (show_output) {
        std::cout << "[INFO] Command succeeded: " + full_cmd << "\n";
    }
}

void clean_old_logs(const fs::path &log_dir, int max_age_seconds) {
    auto now = std::chrono::system_clock::now();
    for (auto &entry : fs::directory_iterator(log_dir)) {
        if (fs::is_regular_file(entry)) {
            auto ftime = fs::last_write_time(entry);
            auto sctp = decltype(ftime)::clock::to_sys(ftime);
            auto age = std::chrono::duration_cast<std::chrono::seconds>(now - sctp).count();
            if (age > max_age_seconds) {
                fs::remove(entry);
            }
        }
    }
}

void create_tarball(const std::string &name, const fs::path &source_dir, const std::vector<std::string> &exclusions) {
    std::string tar_filename = name + "_MAIN.orig.tar.gz";
    std::cout << "[INFO] Creating tarball: " << tar_filename << "\n";

    std::vector<std::string> cmd;
    cmd.push_back("tar");
    for (auto &ex : exclusions) {
        cmd.push_back("--exclude=" + ex);
    }
    cmd.push_back("--exclude=.git/");
    cmd.push_back("-czf");
    cmd.push_back(tar_filename);
    cmd.push_back(fs::path(source_dir).filename().string());

    run_command(cmd, source_dir.parent_path());
    std::cout << "[INFO] Tarball created and compressed: " << tar_filename << "\n";
}

std::string get_current_utc_time() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::tm tm_utc;
    gmtime_r(&now_time, &tm_utc);
    char buf[20];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_utc);
    return std::string(buf);
}
