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

#pragma once

#include <string>
#include <filesystem>
#include <mutex>
#include <regex>
#include <future>
#include <shared_mutex>
#include <semaphore>
#include <functional>
#include <QProcess>

namespace fs = std::filesystem;

class Task;

// Time utilities
std::string get_current_utc_time(const std::string& format);

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

// Function to read the entire content of a file into a string
std::string read_file(const std::filesystem::path& filePath);

// Function to write a string into a file
void write_file(const std::filesystem::path& filePath, const std::string& content);

// Function to perform in-place regex replace on a file
void regex_replace_in_file(const std::filesystem::path& filePath, const std::string& pattern, const std::string& replace);

// Function to decompress gzipped files
std::string decompress_gzip(const std::filesystem::path& filePath);

// Function to download a file with timestamping using libcurl
void download_file_with_timestamping(const std::string& url, const std::filesystem::path& outputPath,
                                  const std::filesystem::path& logFilePath, std::mutex& logMutex);

// Helper function for libcurl write callback
size_t write_data(void* ptr, size_t size, size_t nmemb, void* stream);

// Function to create a temporary directory with a random name
std::filesystem::path create_temp_directory();

// Function to copy a directory recursively
void copy_directory(const std::filesystem::path& source, const std::filesystem::path& destination);

// String utilities
std::vector<std::string> split_string(const std::string& input, const std::string& delimiter);
std::string remove_suffix(const std::string& input, const std::string& suffix);
std::string generate_random_string(size_t length);

// Get version from codename using distro-info
std::pair<int, bool> get_version_from_codename(const std::string& codename);

void run_task_every(std::stop_token _stop_token, int interval_minutes, std::function<void()> task);

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
