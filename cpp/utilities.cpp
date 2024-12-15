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

#include "utilities.h"

#include <fstream>
#include <iostream>
#include <filesystem>
#include <regex>
#include <zlib.h>
#include <curl/curl.h>
#include <sys/stat.h>

namespace fs = std::filesystem;

// Function to read the entire content of a file into a string
std::string readFile(const fs::path& filePath) {
    std::ifstream inFile(filePath, std::ios::binary);
    if (inFile) {
        return std::string((std::istreambuf_iterator<char>(inFile)),
                           std::istreambuf_iterator<char>());
    }
    return "";
}

// Function to write a string into a file
void writeFile(const fs::path& filePath, const std::string& content) {
    std::ofstream outFile(filePath, std::ios::binary);
    if (outFile) {
        outFile << content;
    }
}

// Function to perform in-place regex replace on a file
void regexReplaceInFile(const fs::path& filePath, const std::string& pattern, const std::string& replace) {
    std::string content = readFile(filePath);
    content = std::regex_replace(content, std::regex(pattern), replace);
    writeFile(filePath, content);
}

// Function to decompress gzipped files
std::string decompressGzip(const fs::path& filePath) {
    gzFile infile = gzopen(filePath.c_str(), "rb");
    if (!infile) return "";

    std::string decompressedData;
    char buffer[8192];
    int numRead = 0;
    while ((numRead = gzread(infile, buffer, sizeof(buffer))) > 0) {
        decompressedData.append(buffer, numRead);
    }
    gzclose(infile);
    return decompressedData;
}

// Helper function for libcurl write callback
size_t write_data(void* ptr, size_t size, size_t nmemb, void* stream) {
    FILE* out = static_cast<FILE*>(stream);
    return fwrite(ptr, size, nmemb, out);
}

// Function to download a file with timestamping using libcurl
void downloadFileWithTimestamping(const std::string& url, const fs::path& outputPath,
                                  const fs::path& logFilePath, std::mutex& logMutex) {
    CURL* curl;
    CURLcode res;
    FILE* fp;
    curl = curl_easy_init();
    if (curl) {
        fs::path tempFilePath = outputPath.string() + ".tmp";
        fp = fopen(tempFilePath.c_str(), "wb");

        if (!fp) {
            std::cerr << "Failed to open file: " << tempFilePath << std::endl;
            curl_easy_cleanup(curl);
            return;
        }

        // Set curl options for downloading the file
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

        // Timestamping: set If-Modified-Since header
        struct stat file_info;
        if (stat(outputPath.c_str(), &file_info) == 0) {
            // Set the time condition to If-Modified-Since
            curl_easy_setopt(curl, CURLOPT_TIMECONDITION, CURL_TIMECOND_IFMODSINCE);
            curl_easy_setopt(curl, CURLOPT_TIMEVALUE, file_info.st_mtime);
        }

        // Perform the file download
        res = curl_easy_perform(curl);

        // Get the HTTP response code
        long response_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

        fclose(fp);
        curl_easy_cleanup(curl);

        // Log the result and handle the downloaded file
        {
            std::lock_guard<std::mutex> lock(logMutex);
            std::ofstream logFile(logFilePath, std::ios::app);
            if (res == CURLE_OK && (response_code == 200 || response_code == 201)) {
                fs::rename(tempFilePath, outputPath);
                logFile << "Downloaded: " << url << std::endl;
            } else if (response_code == 304) {
                fs::remove(tempFilePath);
                logFile << "Not Modified: " << url << std::endl;
            } else {
                fs::remove(tempFilePath);
                logFile << "Failed to download: " << url << std::endl;
            }
        }
    } else {
        std::cerr << "Failed to initialize CURL." << std::endl;
    }
}
