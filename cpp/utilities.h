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
#include <future>
#include <semaphore>
#include <functional>

#include <git2.h>

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

// Time utilities
std::string get_current_utc_time(const std::string& format);
std::time_t to_time_t(const std::filesystem::file_time_type& ftime);

// String utilities
std::vector<std::string> split_string(const std::string& input, const std::string& delimiter);
std::string remove_suffix(const std::string& input, const std::string& suffix);
std::string generate_random_string(size_t length);

// Get version from codename using distro-info
std::pair<int, bool> get_version_from_codename(const std::string& codename);

// Git utilities
void ensure_git_inited();

void run_task_every(std::stop_token _stop_token, int interval_minutes, std::function<void()> task);
