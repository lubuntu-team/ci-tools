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

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <thread>
#include <mutex>
#include <regex>
#include <ctime>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <getopt.h>
#include <yaml-cpp/yaml.h>
#include <sstream>

#include "utilities.h"

namespace fs = std::filesystem;

// Function prototypes
void printHelp(const char* programName);
void processRelease(const std::string& release, const YAML::Node& config);
void refresh(const std::string& url, const std::string& pocket, const std::string& britneyCache, std::mutex& logMutex);
int executeAndLog(const std::string& command);

// Execute a command and stream its output to std::cout in real time
int executeAndLog(const std::string& command) {
    std::string fullCommand = command + " 2>&1"; // Redirect stderr to stdout
    FILE* pipe = popen(fullCommand.c_str(), "r");
    if (!pipe) {
        std::cout << "Failed to run command: " << command << std::endl;
        return -1;
    }

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::cout << buffer;
        std::cout.flush(); // Ensure real-time logging
    }

    int exitCode = pclose(pipe);
    if (WIFEXITED(exitCode)) {
        return WEXITSTATUS(exitCode);
    } else {
        return -1; // Abnormal termination
    }
}

int main(int argc, char* argv[]) {
    std::string configFilePath = "config.yaml";

    // Command-line argument parsing
    int opt;
    bool showHelp = false;

    static struct option long_options[] = {
        {"config", required_argument, 0, 'c'},
        {"help",   no_argument,       0, 'h'},
        {0,        0,                 0,  0 }
    };

    while (true) {
        int option_index = 0;
        opt = getopt_long(argc, argv, "c:h", long_options, &option_index);

        if (opt == -1)
            break;

        switch (opt) {
            case 'c':
                configFilePath = optarg;
                break;
            case 'h':
                showHelp = true;
                break;
            default:
                // Unknown option
                showHelp = true;
                break;
        }
    }

    if (showHelp) {
        printHelp(argv[0]);
        return 0;
    }

    // Load configuration from YAML file
    YAML::Node config;
    try {
        config = YAML::LoadFile(configFilePath);
    } catch (const YAML::BadFile& e) {
        std::cerr << "Error: Unable to open config file: " << configFilePath << std::endl;
        return 1;
    } catch (const YAML::ParserException& e) {
        std::cerr << "Error: Failed to parse config file: " << e.what() << std::endl;
        return 1;
    }

    // Ensure LOG_DIR exists
    std::string LOG_DIR = config["LOG_DIR"].as<std::string>();
    fs::create_directories(LOG_DIR);

    // Log rotation: Remove logs older than MAX_LOG_AGE_DAYS
    int maxLogAgeDays = config["MAX_LOG_AGE_DAYS"].as<int>();
    auto now = fs::file_time_type::clock::now(); // Use the same clock as file_time_type

    for (const auto& entry : fs::directory_iterator(LOG_DIR)) {
        if (entry.is_regular_file()) {
            auto ftime = fs::last_write_time(entry.path());
            auto age = std::chrono::duration_cast<std::chrono::hours>(now - ftime).count() / 24;
            if (age > maxLogAgeDays) {
                fs::remove(entry.path());
            }
        }
    }

    // Get the list of releases
    std::vector<std::string> releases = config["RELEASES"].as<std::vector<std::string>>();

    // Process each release
    for (const auto& release : releases) {
        // Log file named by current UTC time (YYYYMMDDTHH:MM:SS) and release
        std::time_t now_c = std::time(nullptr);
        char timestamp[20];
        std::strftime(timestamp, sizeof(timestamp), "%Y%m%dT%H%M%S", std::gmtime(&now_c));
        std::string logFileName = LOG_DIR + "/" + timestamp + "_" + release + ".log";

        // Open log file
        std::ofstream logFile(logFileName, std::ios::app);
        if (!logFile.is_open()) {
            std::cerr << "Error: Unable to open log file: " << logFileName << std::endl;
            continue;
        }

        // Redirect stdout and stderr to log file
        std::streambuf* coutBuf = std::cout.rdbuf();
        std::streambuf* cerrBuf = std::cerr.rdbuf();
        std::cout.rdbuf(logFile.rdbuf());
        std::cerr.rdbuf(logFile.rdbuf());

        // Log the start time
        char startTime[20];
        std::strftime(startTime, sizeof(startTime), "%Y-%m-%d %H:%M:%S", std::gmtime(&now_c));
        std::cout << startTime << " - Running Britney for " << release << std::endl;

        // Process the release
        processRelease(release, config);

        // Restore stdout and stderr
        std::cout.rdbuf(coutBuf);
        std::cerr.rdbuf(cerrBuf);

        // Close log file
        logFile.close();
    }

    return 0;
}

void processRelease(const std::string& RELEASE, const YAML::Node& config) {
    // Extract configuration variables
    std::string MAIN_ARCHIVE = config["MAIN_ARCHIVE"].as<std::string>();
    std::string PORTS_ARCHIVE = config["PORTS_ARCHIVE"].as<std::string>();
    std::string LP_TEAM = config["LP_TEAM"].as<std::string>();
    std::string SOURCE_PPA = config["SOURCE_PPA"].as<std::string>();
    std::string DEST_PPA = config["DEST_PPA"].as<std::string>();
    std::string BRITNEY_CACHE = config["BRITNEY_CACHE"].as<std::string>();
    std::string BRITNEY_DATADIR = config["BRITNEY_DATADIR"].as<std::string>();
    std::string BRITNEY_OUTDIR = config["BRITNEY_OUTDIR"].as<std::string>();
    std::string BRITNEY_HINTDIR = config["BRITNEY_HINTDIR"].as<std::string>();
    std::string BRITNEY_LOC = config["BRITNEY_LOC"].as<std::string>();

    std::vector<std::string> ARCHES = config["ARCHES"].as<std::vector<std::string>>();
    std::vector<std::string> PORTS_ARCHES = config["PORTS_ARCHES"].as<std::vector<std::string>>();

    std::string SOURCE_PPA_URL = "https://ppa.launchpadcontent.net/" + LP_TEAM + "/" + SOURCE_PPA + "/ubuntu/dists/" + RELEASE + "/main";
    std::string DEST_PPA_URL = "https://ppa.launchpadcontent.net/" + LP_TEAM + "/" + DEST_PPA + "/ubuntu/dists/" + RELEASE + "/main";

    // Get current timestamp
    std::time_t now_c = std::time(nullptr);
    char timestamp[20];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d_%H:%M:%S", std::localtime(&now_c));
    std::string BRITNEY_TIMESTAMP(timestamp);

    std::cout << "Release: " << RELEASE << std::endl;
    std::cout << "Timestamp: " << BRITNEY_TIMESTAMP << std::endl;

    // Execute pending-packages script and capture its output
    std::string pendingCmd = "./pending-packages " + RELEASE;
    int pendingResult = executeAndLog(pendingCmd);
    if (pendingResult != 0) {
        std::cerr << "Error: pending-packages script failed for release " << RELEASE << std::endl;
        return;
    }

    std::cout << "Refreshing package indexes..." << std::endl;

    std::vector<std::thread> threads;
    std::mutex logMutex;

    // Refresh package indexes
    std::vector<std::string> pockets = {RELEASE, RELEASE + "-updates"};
    std::vector<std::string> components = {"main", "restricted", "universe", "multiverse"};

    // Loop over pockets, components, architectures to refresh package indexes
    for (const auto& pocket : pockets) {
        for (const auto& component : components) {
            for (const auto& arch : ARCHES) {
                std::string url = MAIN_ARCHIVE + pocket + "/" + component + "/binary-" + arch + "/Packages.gz";
                threads.emplace_back(refresh, url, pocket, BRITNEY_CACHE, std::ref(logMutex));
            }
            for (const auto& arch : PORTS_ARCHES) {
                std::string url = PORTS_ARCHIVE + pocket + "/" + component + "/binary-" + arch + "/Packages.gz";
                threads.emplace_back(refresh, url, pocket, BRITNEY_CACHE, std::ref(logMutex));
            }
            std::string url = MAIN_ARCHIVE + pocket + "/" + component + "/source/Sources.gz";
            threads.emplace_back(refresh, url, pocket, BRITNEY_CACHE, std::ref(logMutex));
        }
    }

    // Treat the destination PPA as just another pocket
    std::string pocket = RELEASE + "-ppa-proposed";
    for (const auto& arch : ARCHES) {
        std::string url = DEST_PPA_URL + "/binary-" + arch + "/Packages.gz";
        threads.emplace_back(refresh, url, pocket, BRITNEY_CACHE, std::ref(logMutex));
    }
    for (const auto& arch : PORTS_ARCHES) {
        std::string url = DEST_PPA_URL + "/binary-" + arch + "/Packages.gz";
        threads.emplace_back(refresh, url, pocket, BRITNEY_CACHE, std::ref(logMutex));
    }
    {
        std::string url = DEST_PPA_URL + "/source/Sources.gz";
        threads.emplace_back(refresh, url, pocket, BRITNEY_CACHE, std::ref(logMutex));
    }

    // Get the source PPA
    pocket = SOURCE_PPA + "-" + RELEASE;
    for (const auto& arch : ARCHES) {
        std::string url = SOURCE_PPA_URL + "/binary-" + arch + "/Packages.gz";
        threads.emplace_back(refresh, url, pocket, BRITNEY_CACHE, std::ref(logMutex));
    }
    for (const auto& arch : PORTS_ARCHES) {
        std::string url = SOURCE_PPA_URL + "/binary-" + arch + "/Packages.gz";
        threads.emplace_back(refresh, url, pocket, BRITNEY_CACHE, std::ref(logMutex));
    }
    {
        std::string url = SOURCE_PPA_URL + "/source/Sources.gz";
        threads.emplace_back(refresh, url, pocket, BRITNEY_CACHE, std::ref(logMutex));
    }

    // Wait for all threads to finish
    for (auto& th : threads) {
        th.join();
    }

    // Process logs and delete them
    pid_t pid = getpid();
    std::string logPattern = std::to_string(pid) + "-wget-log";

    for (auto& p : fs::recursive_directory_iterator(BRITNEY_CACHE)) {
        if (p.is_regular_file()) {
            std::string filename = p.path().filename().string();
            if (filename.find(logPattern) != std::string::npos) {
                // Output log content to stderr
                std::ifstream logFile(p.path());
                if (logFile.is_open()) {
                    std::cerr << logFile.rdbuf();
                    logFile.close();
                }
                fs::remove(p.path());
            }
        }
    }

    std::cout << "Building britney indexes..." << std::endl;

    // Create output directory
    fs::create_directories(fs::path(BRITNEY_OUTDIR) / BRITNEY_TIMESTAMP);

    // "Unstable" is SOURCE_PPA
    std::string DEST = BRITNEY_DATADIR + RELEASE + "-proposed";
    fs::create_directories(DEST);
    fs::create_directories(fs::path(BRITNEY_DATADIR) / (RELEASE + "-proposed") / "state");
    writeFile(fs::path(BRITNEY_DATADIR) / (RELEASE + "-proposed") / "state" / "age-policy-dates", "");

    // Create symlink for Hints
    fs::remove(fs::path(DEST) / "Hints");
    fs::create_symlink(BRITNEY_HINTDIR, fs::path(DEST) / "Hints");

    // Concatenate Sources.gz files for SOURCE_PPA
    std::string sourcesContent;
    for (auto& p : fs::recursive_directory_iterator(BRITNEY_CACHE + SOURCE_PPA + "-" + RELEASE)) {
        if (p.path().filename() == "Sources.gz") {
            sourcesContent += decompressGzip(p.path());
        }
    }
    writeFile(fs::path(DEST) / "Sources", sourcesContent);

    // Concatenate Packages.gz files for SOURCE_PPA
    for (const auto& arch : ARCHES) {
        std::string packagesContent;
        for (auto& p : fs::recursive_directory_iterator(BRITNEY_CACHE + SOURCE_PPA + "-" + RELEASE)) {
            if (p.path().filename() == "Packages.gz" && p.path().parent_path().string().find("binary-" + arch) != std::string::npos) {
                packagesContent += decompressGzip(p.path());
            }
        }
        writeFile(fs::path(DEST) / ("Packages_" + arch), packagesContent);
    }
    for (const auto& arch : PORTS_ARCHES) {
        std::string packagesContent;
        for (auto& p : fs::recursive_directory_iterator(BRITNEY_CACHE + SOURCE_PPA + "-" + RELEASE)) {
            if (p.path().filename() == "Packages.gz" && p.path().parent_path().string().find("binary-" + arch) != std::string::npos) {
                packagesContent += decompressGzip(p.path());
            }
        }
        writeFile(fs::path(DEST) / ("Packages_" + arch), packagesContent);
    }

    writeFile(fs::path(DEST) / "Blocks", "");
    writeFile(fs::path(BRITNEY_DATADIR) / (SOURCE_PPA + "-" + RELEASE) / "Dates", "");

    // Similar steps for "Testing"
    DEST = BRITNEY_DATADIR + RELEASE;
    fs::create_directories(DEST);
    fs::create_directories(fs::path(BRITNEY_DATADIR) / RELEASE / "state");
    writeFile(fs::path(BRITNEY_DATADIR) / RELEASE / "state" / "age-policy-dates", "");

    fs::remove(fs::path(DEST) / "Hints");
    fs::create_symlink(BRITNEY_HINTDIR, fs::path(DEST) / "Hints");

    // Concatenate Sources.gz files for RELEASE
    sourcesContent.clear();
    for (auto& p : fs::recursive_directory_iterator(BRITNEY_CACHE)) {
        if (p.path().filename() == "Sources.gz" && p.path().string().find(RELEASE) != std::string::npos) {
            sourcesContent += decompressGzip(p.path());
        }
    }
    writeFile(fs::path(DEST) / "Sources", sourcesContent);
    // Replace "Section: universe/" with "Section: "
    regexReplaceInFile(fs::path(DEST) / "Sources", "Section: universe/", "Section: ");

    // Concatenate Packages.gz files for RELEASE
    for (const auto& arch : ARCHES) {
        std::string packagesContent;
        for (auto& p : fs::recursive_directory_iterator(BRITNEY_CACHE)) {
            if (p.path().filename() == "Packages.gz" && p.path().string().find(RELEASE) != std::string::npos && p.path().parent_path().string().find("binary-" + arch) != std::string::npos) {
                packagesContent += decompressGzip(p.path());
            }
        }
        fs::path packagesFilePath = fs::path(DEST) / ("Packages_" + arch);
        writeFile(packagesFilePath, packagesContent);
        // Replace "Section: universe/" with "Section: "
        regexReplaceInFile(packagesFilePath, "Section: universe/", "Section: ");
    }
    for (const auto& arch : PORTS_ARCHES) {
        std::string packagesContent;
        for (auto& p : fs::recursive_directory_iterator(BRITNEY_CACHE)) {
            if (p.path().filename() == "Packages.gz" && p.path().string().find(RELEASE) != std::string::npos && p.path().parent_path().string().find("binary-" + arch) != std::string::npos) {
                packagesContent += decompressGzip(p.path());
            }
        }
        fs::path packagesFilePath = fs::path(DEST) / ("Packages_" + arch);
        writeFile(packagesFilePath, packagesContent);
        // Replace "Section: universe/" with "Section: "
        regexReplaceInFile(packagesFilePath, "Section: universe/", "Section: ");
    }

    writeFile(fs::path(DEST) / "Blocks", "");
    writeFile(fs::path(BRITNEY_DATADIR) / (SOURCE_PPA + "-" + RELEASE) / "Dates", "");

    // Create config file atomically
    std::string configContent = readFile("britney.conf");
    // Replace variables in configContent using configuration variables
    configContent = std::regex_replace(configContent, std::regex("\\$\\{RELEASE\\}"), RELEASE);
    configContent = std::regex_replace(configContent, std::regex("\\$\\{BRITNEY_DATADIR\\}"), BRITNEY_DATADIR);
    writeFile("britney.conf", configContent);

    std::cout << "Running britney..." << std::endl;

    // Run britney.py
    std::string britneyCmd = BRITNEY_LOC + " -v --config britney.conf --series " + RELEASE;
    int britneyResult = executeAndLog(britneyCmd);
    if (britneyResult != 0) {
        std::cerr << "Error: Britney execution failed for release " << RELEASE << std::endl;
        return;
    }

    std::cout << "Syncing output to frontend..." << std::endl;
    // Rsync command can be replaced with filesystem copy
    fs::remove_all("output");
    fs::copy("output", "../../output/britney", fs::copy_options::recursive | fs::copy_options::overwrite_existing);

    std::cout << "Moving packages..." << std::endl;

    // Read candidates from HeidiResultDelta
    std::ifstream heidiFile("output/" + RELEASE + "/HeidiResultDelta");
    if (!heidiFile.is_open()) {
        std::cout << "No candidates found for release " << RELEASE << "." << std::endl;
    } else {
        std::ofstream candidatesFile("candidates");
        std::string line;
        while (std::getline(heidiFile, line)) {
            if (line.empty() || line[0] == '#') continue;
            candidatesFile << line << std::endl;
        }
        heidiFile.close();
        candidatesFile.close();

        // Process candidates
        std::ifstream candidates("candidates");
        while (std::getline(candidates, line)) {
            std::istringstream iss(line);
            std::vector<std::string> packageInfo;
            std::string word;
            while (iss >> word) {
                packageInfo.push_back(word);
            }
            if (packageInfo.size() == 2) {
                std::string COPY = "../ubuntu-archive-tools/copy-package";
                std::string REMOVE = "../ubuntu-archive-tools/remove-package";
                if (packageInfo[0][0] == '-') {
                    std::string PACKAGE = packageInfo[0].substr(1);
                    std::cout << "Demoting " << PACKAGE << "..." << std::endl;
                    std::string copyCmd = COPY + " -y -b -s " + RELEASE + " --from ppa:" + LP_TEAM + "/ubuntu/" + DEST_PPA +
                                          " --to ppa:" + LP_TEAM + "/ubuntu/" + SOURCE_PPA + " --version " + packageInfo[1] + " " + PACKAGE;
                    std::string removeCmd = REMOVE + " -y -s " + RELEASE + " --archive ppa:" + LP_TEAM + "/ubuntu/" + DEST_PPA +
                                            " --version " + packageInfo[1] + " --removal-comment=\"demoted to proposed\" " + PACKAGE;
                    int copyResult = executeAndLog(copyCmd);
                    if (copyResult != 0) {
                        std::cerr << "Error: Copy command failed for package " << PACKAGE << std::endl;
                    }
                    int removeResult = executeAndLog(removeCmd);
                    if (removeResult != 0) {
                        std::cerr << "Error: Remove command failed for package " << PACKAGE << std::endl;
                    }
                } else {
                    std::cout << "Migrating " << packageInfo[0] << "..." << std::endl;
                    std::string copyCmd = COPY + " -y -b -s " + RELEASE + " --from ppa:" + LP_TEAM + "/ubuntu/" + SOURCE_PPA +
                                          " --to ppa:" + LP_TEAM + "/ubuntu/" + DEST_PPA + " --version " + packageInfo[1] + " " + packageInfo[0];
                    std::string removeCmd = REMOVE + " -y -s " + RELEASE + " --archive ppa:" + LP_TEAM + "/ubuntu/" + SOURCE_PPA +
                                            " --version " + packageInfo[1] + " --removal-comment=\"moved to release\" " + packageInfo[0];
                    int copyResult = executeAndLog(copyCmd);
                    if (copyResult != 0) {
                        std::cerr << "Error: Copy command failed for package " << packageInfo[0] << std::endl;
                    }
                    int removeResult = executeAndLog(removeCmd);
                    if (removeResult != 0) {
                        std::cerr << "Error: Remove command failed for package " << packageInfo[0] << std::endl;
                    }
                }
            }
        }
        candidates.close();
        fs::remove("candidates");
    }

    std::cout << "Run the grim reaper..." << std::endl;
    std::string grimCmd = "./grim-reaper " + RELEASE;
    int grimResult = executeAndLog(grimCmd);
    if (grimResult != 0) {
        std::cerr << "Error: Grim reaper execution failed for release " << RELEASE << std::endl;
        return;
    }

    std::cout << "Done processing release " << RELEASE << "." << std::endl;
}

void printHelp(const char* programName) {
    std::cout << "Usage: " << programName << " [options]\n";
    std::cout << "Options:\n";
    std::cout << "  -c, --config <file>   Specify path to config file (default: config.yaml)\n";
    std::cout << "  -h, --help            Show this help message and exit\n";
}

// Refresh package indexes by downloading files in parallel
void refresh(const std::string& url, const std::string& pocket, const std::string& britneyCache, std::mutex& logMutex) {
    // Compute directory path based on the URL
    fs::path urlPath(url);
    std::string lastTwoComponents = urlPath.parent_path().parent_path().filename().string() + "/" + urlPath.parent_path().filename().string();
    fs::path dir = fs::path(britneyCache) / pocket / lastTwoComponents;

    // Create necessary directories
    fs::create_directories(dir);

    // Update timestamps to prevent expiration
    auto now = fs::file_time_type::clock::now(); // Use the same clock
    fs::last_write_time(britneyCache, now);
    fs::last_write_time(fs::path(britneyCache) / pocket, now);
    fs::last_write_time(dir.parent_path(), now);
    fs::last_write_time(dir, now);

    // Log file path (uses process ID)
    pid_t pid = getpid();
    fs::path logFilePath = dir / (std::to_string(pid) + "-wget-log");

    // Output file path
    fs::path outputPath = dir / urlPath.filename();

    // Download the file
    downloadFileWithTimestamping(url, outputPath, logFilePath, logMutex);
}
