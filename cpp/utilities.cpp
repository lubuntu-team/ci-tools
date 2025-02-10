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

#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <format>
#include <regex>
#include <sstream>
#include <random>
#include <ranges>
#include <sys/stat.h>
#include <unordered_set>

#include "utilities.h"

#include <zlib.h>
#include <curl/curl.h>

bool verbose = false;

// Define a semaphore with a maximum of 10 concurrent jobs
static std::counting_semaphore<10> sem(10);

// Job queue and synchronization primitives
static std::mutex queue_mutex;
static std::atomic<bool> daemon_running{false};

// Function to decompress gzipped files
std::string decompress_gzip(const fs::path& file_path) {
    gzFile infile = gzopen(file_path.c_str(), "rb");
    if (!infile) return "";

    std::string decompressed_data;
    char buffer[8192];
    int num_read = 0;
    while ((num_read = gzread(infile, buffer, sizeof(buffer))) > 0) {
        decompressed_data.append(buffer, num_read);
    }
    gzclose(infile);
    return decompressed_data;
}

// Helper function for libcurl write callback
size_t write_data(void* ptr, size_t size, size_t nmemb, void* stream) {
    FILE* out = static_cast<FILE*>(stream);
    return fwrite(ptr, size, nmemb, out);
}

// Function to download a file with timestamping using libcurl
void download_file_with_timestamping(const std::string& url,
                                     const fs::path& output_path,
                                     const fs::path& log_file_path,
                                     std::mutex& log_mutex) {
    CURL* curl;
    CURLcode res;
    FILE* fp;
    curl = curl_easy_init();
    if (curl) {
        fs::path temp_file_path = output_path.string() + ".tmp";
        fp = fopen(temp_file_path.c_str(), "wb");

        if (!fp) {
            std::cerr << "Failed to open file: " << temp_file_path << std::endl;
            curl_easy_cleanup(curl);
            return;
        }

        // Set curl options for downloading the file
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

        // Timestamping: set If-Modified-Since header
        struct stat file_info;
        if (stat(output_path.c_str(), &file_info) == 0) {
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
            std::lock_guard<std::mutex> lock(log_mutex);
            std::ofstream log_file(log_file_path, std::ios::app);
            if (res == CURLE_OK && (response_code == 200 || response_code == 201)) {
                fs::rename(temp_file_path, output_path);
                log_file << "Downloaded: " << url << std::endl;
            } else if (response_code == 304) {
                fs::remove(temp_file_path);
                log_file << "Not Modified: " << url << std::endl;
            } else {
                fs::remove(temp_file_path);
                log_file << "Failed to download: " << url << std::endl;
            }
        }
    } else {
        std::cerr << "Failed to initialize CURL." << std::endl;
    }
}

// Function to generate a random string of given length
std::string generate_random_string(size_t length) {
    const std::string chars =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";
    thread_local std::mt19937 rg{std::random_device{}()};
    thread_local std::uniform_int_distribution<> pick(0, chars.size() - 1);
    std::string s;
    s.reserve(length);
    while (length--)
        s += chars[pick(rg)];
    return s;
}

// Function to get current UTC time formatted as per the given format string
std::string get_current_utc_time(const std::string& format) {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::tm tm_utc;
    gmtime_r(&now_time, &tm_utc);
    char buf[64]; // Ensure sufficient buffer size for different formats
    std::strftime(buf, sizeof(buf), format.c_str(), &tm_utc);
    return std::string(buf);
}

std::vector<std::string> split_string(const std::string& input, const std::string& delimiter) {
    std::vector<std::string> result;
    size_t start = 0;
    size_t end = 0;

    while ((end = input.find(delimiter, start)) != std::string::npos) {
        result.emplace_back(input.substr(start, end - start));
        start = end + delimiter.length();
    }

    // Add the remaining part of the string
    result.emplace_back(input.substr(start));
    return result;
}

std::string remove_suffix(const std::string& input, const std::string& suffix) {
    if (input.size() >= suffix.size() &&
        input.compare(input.size() - suffix.size(), suffix.size(), suffix) == 0) {
        return input.substr(0, input.size() - suffix.size());
    }
    return input; // Return the original string if the suffix doesn't exist
}

// Utility which basically does the following:
// "noble" (std::string) -> 2504 (int)
// The bool represents whether this codename is the development release
std::pair<int, bool> get_version_from_codename(const std::string& codename) {
    std::ifstream file("/usr/share/distro-info/ubuntu.csv");
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file.");
    }

    std::string line;
    // Skip the header line
    std::getline(file, line);

    std::string last_codename;
    int version = 0;

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string version_str, name, series;
        std::getline(iss, version_str, ',');
        std::getline(iss, name, ',');
        std::getline(iss, series, ',');

        if (series == codename) {
            version_str.erase(std::remove(version_str.begin(), version_str.end(), '.'),
                              version_str.end());
            version = std::stoi(version_str);
        }
        last_codename = series;
    }

    bool is_last = (codename == last_codename);

    if (version == 0) {
        throw std::runtime_error("Codename not found.");
    }

    return {version, is_last};
}

void run_task_every(std::stop_token _stop_token, int interval_minutes, std::function<void()> task) {
    if (interval_minutes < 2) interval_minutes = 2;
    std::this_thread::sleep_for(std::chrono::minutes(interval_minutes / 2));

    while (!_stop_token.stop_requested()) {
        task();
        std::this_thread::sleep_for(std::chrono::minutes(interval_minutes));
    }
}

// Logger function implementations
void log_info(const std::string &msg) {
    std::cout << "[INFO] " << msg << "\n";
}

void log_warning(const std::string &msg) {
    std::cerr << "[WARNING] " << msg << "\n";
}

void log_error(const std::string &msg) {
    std::cerr << "[ERROR] " << msg << "\n";
}

void log_verbose(const std::string &msg) {
    if (verbose) {
        std::cout << "[VERBOSE] " << msg << "\n";
    }
}

bool run_command(const std::vector<std::string> &cmd,
                 const std::optional<std::filesystem::path> &cwd,
                 bool show_output,
                 std::shared_ptr<Log> log) {
    if (cmd.empty()) {
        throw std::runtime_error("Command is empty");
    }

    QProcess process;

    // Set the working directory if provided
    if (cwd) {
        process.setWorkingDirectory(QString::fromStdString(cwd->string()));
    }

    // Set up the environment (if needed)
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    process.setProcessEnvironment(env);

    // Extract executable and arguments
    QString program = QString::fromStdString(cmd[0]);
    QStringList arguments;
    for (size_t i = 1; i < cmd.size(); ++i) {
        arguments << QString::fromStdString(cmd[i]);
    }

    // Start the command
    process.start(program, arguments);
    if (!process.waitForStarted()) {
        throw std::runtime_error("Failed to start the command: " + program.toStdString());
    }

    // Stream output while the process is running
    while (process.state() == QProcess::Running) {
        if (process.waitForReadyRead()) {
            QByteArray output = process.readAllStandardOutput();
            QByteArray error = process.readAllStandardError();

            if (log) {
                log->append(output.toStdString());
                log->append(error.toStdString());
            }

            if (show_output) {
                std::cout << output.toStdString();
                std::cerr << error.toStdString();
            }
        }
    }

    // Wait for the process to finish
    process.waitForFinished();

    // Capture return code and errors
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        QByteArray error_output = process.readAllStandardError();
        std::string error_message = "Command failed with exit code: " + std::to_string(process.exitCode());
        if (!error_output.isEmpty()) {
            error_message += "\nError Output: " + error_output.toStdString();
        }
        throw std::runtime_error(error_message);
    }

    return true;
}
