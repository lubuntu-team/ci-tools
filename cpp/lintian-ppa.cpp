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
#include "utilities.h"

#include "launchpad.h"
#include "archive.h"
#include "distribution.h"
#include "distro_series.h"
#include "person.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <filesystem>
#include <mutex>
#include <thread>
#include <future>
#include <condition_variable>
#include <queue>
#include <chrono>
#include <ctime>
#include <getopt.h>
#include <regex>
#include <uuid/uuid.h>
#include <cstdlib>
#include <cstdio>

namespace fs = std::filesystem;

// Global variables for logging
std::mutex logMutex;
std::ofstream globalLogFile;

// Function to log informational messages
void log_info_custom(const std::string &msg) {
    std::lock_guard<std::mutex> lock(logMutex);
    if (globalLogFile.is_open()) {
        auto now = std::chrono::system_clock::now();
        std::time_t now_c = std::chrono::system_clock::to_time_t(now);
        char timebuf[20];
        std::strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", std::gmtime(&now_c));
        globalLogFile << timebuf << " - INFO - " << msg << "\n";
        globalLogFile.flush();
    }
}

// Function to log error messages
void log_error_custom(const std::string &msg) {
    std::lock_guard<std::mutex> lock(logMutex);
    if (globalLogFile.is_open()) {
        auto now = std::chrono::system_clock::now();
        std::time_t now_c = std::chrono::system_clock::to_time_t(now);
        char timebuf[20];
        std::strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", std::gmtime(&now_c));
        globalLogFile << timebuf << " - ERROR - " << msg << "\n";
        globalLogFile.flush();
    }
}

// Simple thread pool implementation
class ThreadPool {
public:
    ThreadPool(size_t maxThreads) : stopFlag(false) {
        for (size_t i = 0; i < maxThreads; ++i) {
            workers.emplace_back([this]() {
                while (true) {
                    std::function<void()> task;

                    {
                        std::unique_lock<std::mutex> lock(this->queueMutex);
                        this->condition.wait(lock, [this]() { return this->stopFlag || !this->tasks.empty(); });
                        if (this->stopFlag && this->tasks.empty())
                            return;
                        task = std::move(this->tasks.front());
                        this->tasks.pop();
                    }

                    task();
                }
            });
        }
    }

    // Submit a task to the pool
    template<class F>
    void enqueue(F&& f) {
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            if (stopFlag)
                throw std::runtime_error("Enqueue on stopped ThreadPool");
            tasks.emplace(std::forward<F>(f));
        }
        condition.notify_one();
    }

    // Destructor joins all threads
    ~ThreadPool() {
        {
            std::lock_guard<std::mutex> lock(queueMutex);
            stopFlag = true;
        }
        condition.notify_all();
        for (std::thread &worker: workers)
            worker.join();
    }

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;

    std::mutex queueMutex;
    std::condition_variable condition;
    bool stopFlag;
};

// Function to parse command-line arguments
struct Arguments {
    std::string user;
    std::string ppa;
    std::optional<std::string> ppa2;
    std::optional<std::string> override_output;
};

Arguments parseArguments(int argc, char* argv[]) {
    Arguments args;
    int opt;
    bool showHelp = false;

    static struct option long_options[] = {
        {"user", required_argument, 0, 'u'},
        {"ppa", required_argument, 0, 'p'},
        {"ppa2", required_argument, 0, '2'},
        {"override-output", required_argument, 0, 'o'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "u:p:2:o:h", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'u':
                args.user = optarg;
                break;
            case 'p':
                args.ppa = optarg;
                break;
            case '2':
                args.ppa2 = optarg;
                break;
            case 'o':
                args.override_output = optarg;
                break;
            case 'h':
            default:
                std::cout << "Usage: " << argv[0] << " --user <user> --ppa <ppa> [--ppa2 <ppa2>] [--override-output <path>]\n";
                exit(0);
        }
    }

    if (args.user.empty() || args.ppa.empty()) {
        std::cerr << "Error: --user and --ppa are required arguments.\n";
        std::cout << "Usage: " << argv[0] << " --user <user> --ppa <ppa> [--ppa2 <ppa2>] [--override-output <path>]\n";
        exit(1);
    }

    return args;
}

// Function to parse the Changes file and extract Source and Architecture
struct ChangesInfo {
    std::string source;
    std::string architecture;
};

std::optional<ChangesInfo> parse_changes_file(const fs::path& changesPath) {
    if (!fs::exists(changesPath)) {
        log_error_custom("Changelog not found: " + changesPath.string());
        return std::nullopt;
    }

    std::ifstream infile(changesPath);
    if (!infile.is_open()) {
        log_error_custom("Unable to open changelog: " + changesPath.string());
        return std::nullopt;
    }

    ChangesInfo info;
    std::string line;
    while (std::getline(infile, line)) {
        if (line.empty())
            break; // End of headers
        if (line.find("Source:") == 0) {
            info.source = line.substr(7);
            // Trim whitespace
            info.source.erase(0, info.source.find_first_not_of(" \t"));
        }
        if (line.find("Architecture:") == 0) {
            info.architecture = line.substr(13);
            // Trim whitespace
            info.architecture.erase(0, info.architecture.find_first_not_of(" \t"));
        }
    }

    infile.close();

    if (info.source.empty() || info.architecture.empty()) {
        log_error_custom("Invalid changelog format in: " + changesPath.string());
        return std::nullopt;
    }

    return info;
}

// Function to run lintian and capture its output
std::optional<std::string> run_lintian(const fs::path& changesPath) {
    std::vector<std::string> lintianCmd = {"lintian", "-EvIL", "+pedantic", changesPath.filename().string()};
    try {
        // Redirect stdout and stderr to capture output
        std::string command = "lintian -EvIL +pedantic \"" + changesPath.string() + "\"";
        std::array<char, 128> buffer;
        std::string result;
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
        if (!pipe) {
            log_error_custom("Failed to run lintian command.");
            return std::nullopt;
        }
        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            result += buffer.data();
        }
        return result;
    } catch (...) {
        log_error_custom("Exception occurred while running lintian.");
        return std::nullopt;
    }
}

// Function to process a single changes file URL
void process_sources(const std::string& url, const fs::path& baseOutputDir, const fs::path& lintianTmpDir) {
    // Generate a unique temporary directory
    uuid_t uuid_bytes;
    uuid_generate(uuid_bytes); // Correctly call with one argument

    char uuid_cstr[37]; // UUIDs are 36 characters plus null terminator
    uuid_unparse_lower(uuid_bytes, uuid_cstr); // Convert to string

    std::string uuid_str = std::string(uuid_cstr).substr(0, 8); // Extract first 8 characters
    std::string tmpdir = (baseOutputDir / ("lintian_tmp_" + uuid_str)).string();

    // Create temporary directory
    fs::create_directories(tmpdir);

    // Extract the changes file name from URL
    std::string changes_file = url.substr(url.find_last_of('/') + 1);

    log_info_custom("Downloading " + changes_file + " via dget.");

    // Run dget -u <url> in the temporary directory
    std::vector<std::string> dgetCmd = {"dget", "-u", url};
    try {
        run_command(dgetCmd, tmpdir);
    } catch (const std::exception& e) {
        log_error_custom("dget command failed for URL: " + url);
        fs::remove_all(tmpdir);
        return;
    }

    // Parse the Changes file
    fs::path changesPath = fs::path(tmpdir) / changes_file;
    auto changesInfoOpt = parse_changes_file(changesPath);
    if (!changesInfoOpt.has_value()) {
        fs::remove_all(tmpdir);
        return;
    }

    ChangesInfo changesInfo = changesInfoOpt.value();

    // Handle Architecture field
    std::string arch = changesInfo.architecture;
    arch = std::regex_replace(arch, std::regex("all"), "");
    arch = std::regex_replace(arch, std::regex("_translations"), "");
    std::istringstream iss(arch);
    std::string arch_clean;
    iss >> arch_clean;
    if (arch_clean.empty()) {
        fs::remove_all(tmpdir);
        return;
    }

    log_info_custom("Running Lintian for " + changesInfo.source + " on " + arch_clean);

    // Run lintian and capture output
    auto lintianOutputOpt = run_lintian(changesPath);
    if (!lintianOutputOpt.has_value()) {
        fs::remove_all(tmpdir);
        return;
    }
    std::string lintianOutput = lintianOutputOpt.value();

    // Write lintian output to lintian_tmp/source/<arch>.txt
    fs::path outputPath = lintianTmpDir / changesInfo.source;
    fs::create_directories(outputPath);
    fs::path archOutputFile = outputPath / (arch_clean + ".txt");
    try {
        writeFile(archOutputFile, lintianOutput);
    } catch (const std::exception& e) {
        log_error_custom("Failed to write lintian output for " + changesInfo.source + " on " + arch_clean);
    }

    // Remove temporary directory
    fs::remove_all(tmpdir);
}

// Function to perform rsync-like copy
void rsync_copy(const fs::path& source, const fs::path& destination) {
    try {
        if (!fs::exists(destination)) {
            fs::create_directories(destination);
        }
        for (const auto& entry : fs::recursive_directory_iterator(source)) {
            const auto& path = entry.path();
            auto relativePath = fs::relative(path, source);
            fs::path destPath = destination / relativePath;

            if (fs::is_symlink(path)) {
                if (fs::exists(destPath) || fs::is_symlink(destPath)) {
                    fs::remove(destPath);
                }
                auto target = fs::read_symlink(path);
                fs::create_symlink(target, destPath);
            } else if (fs::is_directory(path)) {
                fs::create_directories(destPath);
            } else if (fs::is_regular_file(path)) {
                fs::copy_file(path, destPath, fs::copy_options::overwrite_existing);
            }
        }
    } catch (const std::exception& e) {
        log_error_custom("rsync_copy failed from " + source.string() + " to " + destination.string() + ": " + e.what());
    }
}

int main(int argc, char* argv[]) {
    // Parse command-line arguments
    Arguments args = parseArguments(argc, argv);

    // Set BASE_OUTPUT_DIR
    std::string BASE_OUTPUT_DIR = "/srv/lubuntu-ci/output/";
    if (args.override_output.has_value()) {
        BASE_OUTPUT_DIR = args.override_output.value();
    }

    // Set LOG_DIR
    fs::path LOG_DIR = fs::path(BASE_OUTPUT_DIR) / "logs" / "lintian";
    fs::create_directories(LOG_DIR);

    // Create log file with current UTC timestamp
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    char timestamp[20];
    std::strftime(timestamp, sizeof(timestamp), "%Y%m%dT%H%M%S", std::gmtime(&now_c));
    fs::path logFilePath = LOG_DIR / (std::string(timestamp) + ".log");

    // Open global log file
    globalLogFile.open(logFilePath, std::ios::app);
    if (!globalLogFile.is_open()) {
        std::cerr << "Error: Unable to open log file: " << logFilePath << std::endl;
        return 1;
    }

    log_info_custom("Starting lintian-ppa.");

    // Authenticate with Launchpad
    log_info_custom("Logging into Launchpad...");
    auto lp_opt = launchpad::login();
    if (!lp_opt.has_value()) {
        std::cerr << "Failed to authenticate with Launchpad.\n";
        return 1;
    }
    auto lp = lp_opt.value().get();

    auto ubuntu_opt = lp->distributions["ubuntu"];
    distribution ubuntu = ubuntu_opt.value();
    auto ds_opt = ubuntu.current_series;
    distro_series current_series = ds_opt.value();

    // Retrieve user and PPA
    auto user_opt = lp->people[args.user];
    person user = user_opt.value();

    auto ppa_opt = user.getPPAByName(ubuntu, args.ppa);
    if (!ppa_opt.has_value()) {
        log_error_custom("Failed to retrieve PPA: " + args.ppa);
        return 1;
    }
    archive ppa = ppa_opt.value();
    log_info_custom("Retrieved PPA: " + args.ppa);

    std::optional<archive> ppa2_opt;
    if (args.ppa2.has_value()) {
        auto ppa2_found = user.getPPAByName(ubuntu, args.ppa2.value());
        if (!ppa2_found.has_value()) {
            log_error_custom("Failed to retrieve PPA2: " + args.ppa2.value());
            return 1;
        }
        ppa2_opt = ppa2_found.value();
        log_info_custom("Retrieved PPA2: " + args.ppa2.value());
    }

    // Set up lintian directories
    fs::path lintianDir = fs::path(BASE_OUTPUT_DIR) / "lintian";
    fs::path lintianTmpDir;
    {
        std::string uuid_str;
        uuid_t uuid_bytes;
        uuid_generate(uuid_bytes);
        char uuid_cstr[37];
        uuid_unparse(uuid_bytes, uuid_cstr);
        uuid_str = std::string(uuid_cstr);
        // Truncate UUID to first 8 characters
        uuid_str = uuid_str.substr(0, 8);
        lintianTmpDir = fs::path(BASE_OUTPUT_DIR) / ("lintian_tmp_" + uuid_str);
    }
    fs::create_directories(lintianDir);
    fs::create_directories(lintianTmpDir);

    // Initialize ThreadPool with 5 threads
    ThreadPool pool(5);

    // Mutex for managing the published sources iterator
    std::mutex sourcesMutex;

    // Function to iterate over published sources and enqueue tasks
    auto main_source_iter = [&](ThreadPool& poolRef, std::vector<std::future<void>>& futures) {
        // Path to .LAST_RUN file
        fs::path lastRunFile = lintianDir / ".LAST_RUN";
        std::chrono::system_clock::time_point lastRunTime = std::chrono::system_clock::now() - std::chrono::hours(24*365);

        if (fs::exists(lastRunFile)) {
            std::ifstream infile(lastRunFile);
            if (infile.is_open()) {
                std::string lastRunStr;
                std::getline(infile, lastRunStr);
                infile.close();
                std::tm tm = {};
                std::istringstream ss(lastRunStr);
                ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%S");
                if (!ss.fail()) {
                    lastRunTime = std::chrono::system_clock::from_time_t(timegm(&tm));
                    log_info_custom("Last run time: " + lastRunStr);
                } else {
                    log_error_custom("Invalid format in .LAST_RUN file.");
                }
            }
        } else {
            log_info_custom(".LAST_RUN file does not exist. Using default last run time.");
        }

        // Update .LAST_RUN with current time
        {
            std::ofstream outfile(lastRunFile, std::ios::trunc);
            if (outfile.is_open()) {
                auto currentTime = std::chrono::system_clock::now();
                std::time_t currentTime_c = std::chrono::system_clock::to_time_t(currentTime);
                char timebuf[20];
                std::strftime(timebuf, sizeof(timebuf), "%Y-%m-%dT%H:%M:%S", std::gmtime(&currentTime_c));
                outfile << timebuf;
                outfile.close();
                log_info_custom("Updated .LAST_RUN with current time: " + std::string(timebuf));
            } else {
                log_error_custom("Failed to update .LAST_RUN file.");
            }
        }

        // Iterate over published sources
        auto publishedSources = ppa.getPublishedSources("Published", current_series.name);
        for (const auto& source : publishedSources) {
            for (const auto& build : source.getBuilds()) {
                if (build.buildstate == "Successfully built") {
                    // Assuming build.datebuilt is a std::chrono::system_clock::time_point
                    if (build.datebuilt >= lastRunTime) {
                        // Enqueue the process_sources task
                        poolRef.enqueue([=]() {
                            process_sources(build.changesfile_url, fs::path(BASE_OUTPUT_DIR), lintianTmpDir);
                        });
                    }
                }
            }
        }
    };

    // Start main_source_iter in the thread pool
    std::vector<std::future<void>> futures;
    pool.enqueue([&]() { main_source_iter(pool, futures); });

    // Wait for all tasks to complete by destructing the pool
    // The ThreadPool destructor will wait for all tasks to finish
    // So no additional synchronization is needed here

    // After all tasks are done, perform rsync
    log_info_custom("All lintian tasks completed. Syncing temporary lintian data to final directory.");
    rsync_copy(lintianTmpDir, lintianDir);

    // Remove temporary lintian directory
    fs::remove_all(lintianTmpDir);

    // Clean old logs
    clean_old_logs(LOG_DIR, 86400); // 1 day in seconds, adjust as needed

    log_info_custom("Lintian-ppa processing completed successfully.");

    // Close the global log file
    if (globalLogFile.is_open()) {
        globalLogFile.close();
    }

    return 0;
}
