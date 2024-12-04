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

#ifndef UTILITIES_H
#define UTILITIES_H

#include <string>
#include <filesystem>
#include <mutex>

// Function to read the entire content of a file into a string
std::string readFile(const std::filesystem::path& filePath);

// Function to write a string into a file
void writeFile(const std::filesystem::path& filePath, const std::string& content);

// Function to perform in-place regex replace on a file
void regexReplaceInFile(const std::filesystem::path& filePath, const std::string& pattern, const std::string& replace);

// Function to decompress gzipped files
std::string decompressGzip(const std::filesystem::path& filePath);

// Function to download a file with timestamping using libcurl
void downloadFileWithTimestamping(const std::string& url, const std::filesystem::path& outputPath,
                                  const std::filesystem::path& logFilePath, std::mutex& logMutex);

// Helper function for libcurl write callback
size_t write_data(void* ptr, size_t size, size_t nmemb, void* stream);

#endif // UTILITIES_H
