// Copyright (C) 2025 Simon Quigley <tsimonq2@ubuntu.com>
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

#include <cstring>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <format>
#include <regex>
#include <sstream>

#include "fs_common.h"
#include "utilities.h"

namespace fs = std::filesystem;

// Function to read the entire content of a file into a string
std::string read_file(const fs::path& file_path) {
    std::ifstream in_file(file_path, std::ios::binary);
    if (in_file) return std::string((std::istreambuf_iterator<char>(in_file)),
                                    std::istreambuf_iterator<char>());
    return "";
}

// Function to write a string into a file
void write_file(const fs::path& file_path, const std::string& content) {
    std::ofstream out_file(file_path, std::ios::binary);
    if (out_file) out_file << content;
}

// Function to perform in-place regex replace on a file
void regex_replace_in_file(const fs::path& file_path, const std::string& pattern, const std::string& replacement) {
    std::string content = read_file(file_path);
    content = std::regex_replace(content, std::regex(pattern), replacement);
    write_file(file_path, content);
}

std::filesystem::path create_temp_directory() {
    auto temp_dir = std::filesystem::temp_directory_path() / generate_random_string(32);
    std::filesystem::create_directory(temp_dir);
    return temp_dir;
}

// Function to copy a directory recursively
void copy_directory(const fs::path& source, const fs::path& destination) {
    if (!std::filesystem::exists(source) || !std::filesystem::is_directory(source)) throw std::runtime_error("Source directory does not exist or is not a directory: " + source.string());

    // Create the destination directory
    std::filesystem::create_directories(destination);

    // Copy files and directories recursively
    for (const auto& entry : std::filesystem::recursive_directory_iterator(source)) {
        auto relative_path = std::filesystem::relative(entry.path(), source);
        auto target_path = destination / relative_path;

        try {
            if (std::filesystem::is_directory(entry)) std::filesystem::create_directory(target_path);
            else if (std::filesystem::is_regular_file(entry)) std::filesystem::copy(entry, target_path, std::filesystem::copy_options::overwrite_existing);
        } catch (...) {
            continue;
        }
    }
}

// Function to extract excluded files from a copyright file
std::vector<std::string> extract_files_excluded(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) throw std::runtime_error("Failed to open file: " + filepath);

    std::vector<std::string> files_excluded;
    std::string line;
    std::regex files_excluded_pattern(R"(Files-Excluded:\s*(.*))");
    bool in_files_excluded = false;

    while (std::getline(file, line)) {
        if (std::regex_match(line, files_excluded_pattern)) {
            in_files_excluded = true;
            std::smatch match;
            if (std::regex_search(line, match, files_excluded_pattern) && match.size() > 1) files_excluded.emplace_back(match[1]);
        } else if (in_files_excluded) {
            if (!line.empty() && (line[0] == ' ' || line[0] == '\t')) files_excluded.emplace_back(line.substr(1));
            else break; // End of Files-Excluded block
        }
    }

    return files_excluded;
}
