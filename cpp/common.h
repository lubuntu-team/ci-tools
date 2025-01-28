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

#ifndef COMMON_H
#define COMMON_H

#include "utilities.h"
#include <string>
#include <optional>
#include <filesystem>
#include <shared_mutex>
#include <mutex>
#include <vector>
#include <regex>

namespace fs = std::filesystem;
class Task;

class Log {
private:
    std::string data = "";
    mutable std::shared_mutex lock_;
    std::weak_ptr<Task> task_context_;
    std::string last_data_str = "";

public:
    void append(const std::string& str) {
        std::unique_lock lock(lock_);
        std::string log_str = str.ends_with('\n') ? str : str + '\n';
        if (str.empty() || last_data_str == log_str) { return; }
        else if (str.contains("dpkg-source: warning: ignoring deletion of file")) { return; }
        data += std::format("[{}] {}", get_current_utc_time("%Y-%m-%dT%H:%M:%SZ"), log_str);
        last_data_str = log_str;
    }

    void set_log(const std::string& str) {
        std::unique_lock lock(lock_);
        data = str;
    }

    std::string get() const {
        std::shared_lock lock(lock_);
        return std::regex_replace(data, std::regex(R"(^\s+)"), "");
    }

    void assign_task_context(std::shared_ptr<Task> task) {
        task_context_ = task;
    }

    std::shared_ptr<Task> get_task_context() const {
        return task_context_.lock();
    }
};

// Logger functions
extern bool verbose;
void log_info(const std::string &msg);
void log_warning(const std::string &msg);
void log_error(const std::string &msg);
void log_verbose(const std::string &msg);

// Function to run a command with optional working directory and show output
bool run_command(const std::vector<std::string> &cmd,
                 const std::optional<fs::path> &cwd = std::nullopt,
                 bool show_output = false,
                 std::shared_ptr<Log> log = nullptr);

// Function to extract excluded files from a copyright file
std::vector<std::string> extract_files_excluded(const std::string& filepath);

// Function to create a tarball
void create_tarball(const std::string& tarballPath,
                    const std::string& directory,
                    const std::vector<std::string>& exclusions,
                    std::shared_ptr<Log> log = nullptr);

#endif // COMMON_H
