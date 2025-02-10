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

#include <filesystem>
#include <regex>
#include <vector>

namespace fs = std::filesystem;

// Function to read the entire content of a file into a string
std::string read_file(const std::filesystem::path& file_path);

// Function to write a string into a file
void write_file(const std::filesystem::path& file_path, const std::string& content);

// Function to perform in-place regex replace on a file
void regex_replace_in_file(const std::filesystem::path& file_path, const std::string& pattern, const std::string& replace);

// Function to create a temporary directory with a random name
std::filesystem::path create_temp_directory();

// Function to copy a directory recursively
void copy_directory(const std::filesystem::path& source, const std::filesystem::path& destination);

// Function to extract excluded files from a copyright file
std::vector<std::string> extract_files_excluded(const std::string& filepath);
