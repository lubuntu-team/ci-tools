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

#include "launchpad.h"
#include "archive.h"
#include "build.h"
#include "distribution.h"
#include "person.h"
#include "source_package_publishing_history.h"

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
#include <optional>
#include <unordered_set>
#include <set>

namespace fs = std::filesystem;

// Function prototypes
void printHelp(const char* programName);
void processRelease(const std::string& release, const YAML::Node& config);
void refresh(const std::string& url, const std::string& pocket, const std::string& britneyCache, std::mutex& logMutex);
int executeAndLog(const std::string& command);

// Change global_lp_opt to match login() return type
static std::optional<std::shared_ptr<launchpad>> global_lp_opt;
static launchpad* global_lp = nullptr;

// Execute a command and stream its output to std::cout in real time
int executeAndLog(const std::string& command) {
    std::string fullCommand = command + " 2>&1";
    FILE* pipe = popen(fullCommand.c_str(), "r");
    if (!pipe) {
        std::cout << "Failed to run command: " << command << std::endl;
        return -1;
    }

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::cout << buffer;
        std::cout.flush();
    }

    int exitCode = pclose(pipe);
    if (WIFEXITED(exitCode)) {
        return WEXITSTATUS(exitCode);
    } else {
        return -1;
    }
}

// Helper to count entries in a generator
template<typename T>
int count_generator(T gen) {
    int c = 0;
    for (auto _ : gen) {
        (void)_;
        c++;
    }
    return c;
}

int check_pending_packages(const std::string& release) {
    if (!global_lp_opt.has_value()) {
        auto lp_opt = launchpad::login();
        if (!lp_opt.has_value()) {
            std::cerr << "Failed to authenticate with Launchpad.\n";
            return 1;
        }
        global_lp_opt = lp_opt;
        global_lp = global_lp_opt.value().get();
    }

    auto lp = global_lp;

    std::cout << "Logging into Launchpad..." << std::endl;
    std::cout << "Logged in. Initializing repositories..." << std::endl;

    auto ubuntu_opt = lp->distributions["ubuntu"];
    if (!ubuntu_opt.has_value()) {
        std::cerr << "Failed to retrieve ubuntu.\n";
        return 1;
    }
    distribution ubuntu = ubuntu_opt.value();

    auto lubuntu_ci_opt = lp->people["lubuntu-ci"];
    if (!lubuntu_ci_opt.has_value()) {
        std::cerr << "Failed to retrieve lubuntu-ci.\n";
        return 1;
    }
    person lubuntu_ci = lubuntu_ci_opt.value();

    auto regular_opt = lubuntu_ci.getPPAByName(ubuntu, "unstable-ci");
    if (!regular_opt.has_value()) {
        std::cerr << "Failed to retrieve regular PPA.\n";
        return 1;
    }
    archive regular = regular_opt.value();

    auto proposed_opt = lubuntu_ci.getPPAByName(ubuntu, "unstable-ci-proposed");
    if (!proposed_opt.has_value()) {
        std::cerr << "Failed to retrieve proposed PPA.\n";
        return 1;
    }
    archive proposed = proposed_opt.value();

    auto series_opt = ubuntu.getSeries(release);
    if (!series_opt.has_value()) {
        std::cerr << "Failed to retrieve series for: " << release << std::endl;
        return 1;
    }
    distro_series series = series_opt.value();

    std::cout << "Repositories initialized. Checking for pending sources..." << std::endl;

    {
        auto reg_pending_gen = regular.getPublishedSources("", "", series, false, false, "", "", "Pending", "");
        int reg_pending_count = 0;
        for (auto s : reg_pending_gen) reg_pending_count++;
        auto prop_pending_gen = proposed.getPublishedSources("", "", series, false, false, "", "", "Pending", "");
        int prop_pending_count = 0;
        for (auto s : prop_pending_gen) prop_pending_count++;

        int total_pending = reg_pending_count + prop_pending_count;

        if (total_pending != 0) {
            std::cout << "Total sources pending: " << total_pending << std::endl;
            std::cout << "Sources are still pending, not running Britney" << std::endl;
            return 1;
        }
    }

    std::cout << "No pending sources, continuing. Checking for pending builds..." << std::endl;
    {
        int total_pending = 0;
        int total_retried = 0;
        auto now_utc = std::chrono::system_clock::now();
        auto one_hour_ago = now_utc - std::chrono::hours(1);

        for (auto& archv : {proposed, regular}) {
            auto published_gen = archv.getPublishedSources("", "", series, false, false, "", "", "Published", "");
            std::vector<source_package_publishing_history> published;
            for (auto s : published_gen) published.push_back(s);

            for (auto &src : published) {
                for (auto build : src.getBuilds()) {
                    auto bs = build.buildstate;
                    if (bs == "Currently building") {
                        if (build.date_started >= one_hour_ago) {
                            total_pending += 1;
                        }
                    } else if (bs == "Needs building") {
                        total_pending += 1;
                    } else if (bs == "Chroot problem" ||
                               (bs == "Failed to build" && build.build_log_url.empty())) {
                        if (build.can_be_retried) {
                            if (build.retry()) {
                                total_pending += 1;
                                total_retried += 1;
                            }
                        }
                    }
                }
            }
        }

        if (total_retried != 0) {
            std::cout << "Total builds retried due to builder flakiness: " << total_retried << std::endl;
        }

        if (total_pending != 0) {
            std::cout << "Total builds pending: " << total_pending << std::endl;
            std::cout << "Builds are still running, not running Britney" << std::endl;
            return 1;
        }
    }

    std::cout << "No pending builds, continuing. Checking for pending binaries..." << std::endl;
    {
        bool has_pending = false;

        for (auto& pocket : {proposed, regular}) {
            if (has_pending) break;
            auto three_hours_ago = std::chrono::system_clock::now() - std::chrono::hours(3);
            std::set<std::string> check_builds;
            std::set<std::string> current_builds;
            std::vector<source_package_publishing_history> source_packages;

            auto records_gen = pocket.getBuildRecords("Successfully built");
            std::vector<build> records;
            for (auto br : records_gen) records.push_back(br);

            for (auto &build_record : records) {
                if (build_record.datebuilt < three_hours_ago) {
                    source_packages.clear();
                    break;
                }
                check_builds.insert(build_record.title);
                if (build_record.current_source_publication.has_value()) {
                    auto src_pub = build_record.current_source_publication.value();
                    if (src_pub.distro_series.value().name == series.name) {
                        bool found = false;
                        for (auto& sp : source_packages) {
                            if (sp.self_link == src_pub.self_link) {
                                found = true;
                                break;
                            }
                        }
                        if (!found) {
                            source_packages.emplace_back(src_pub);
                        }
                    }
                }
            }

            for (auto& s : source_packages) {
                for (auto bin : s.getPublishedBinaries()) {
                    current_builds.insert(bin.build.title);
                }
            }

            for (auto& cb : current_builds) {
                if (check_builds.find(cb) == check_builds.end()) {
                    has_pending = true;
                    break;
                }
            }
        }

        if (has_pending) {
            std::cout << "Binaries are still pending, not running Britney" << std::endl;
            return 1;
        }
    }

    std::cout << "All clear. Starting Britney." << std::endl;

    return 0;
}


int main(int argc, char* argv[]) {
    std::string configFilePath = "config.yaml";

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
                showHelp = true;
                break;
        }
    }

    if (showHelp) {
        printHelp(argv[0]);
        return 0;
    }

    YAML::Node config;
    try {
        config = YAML::LoadFile(configFilePath);
    } catch (const YAML::BadFile&) {
        std::cerr << "Error: Unable to open config file: " << configFilePath << std::endl;
        return 1;
    } catch (const YAML::ParserException& e) {
        std::cerr << "Error: Failed to parse config file: " << e.what() << std::endl;
        return 1;
    }

    std::string LOG_DIR = config["LOG_DIR"].as<std::string>();
    fs::create_directories(LOG_DIR);

    int maxLogAgeDays = config["MAX_LOG_AGE_DAYS"].as<int>();
    auto now = fs::file_time_type::clock::now();

    for (const auto& entry : fs::directory_iterator(LOG_DIR)) {
        if (entry.is_regular_file()) {
            auto ftime = fs::last_write_time(entry.path());
            auto age = std::chrono::duration_cast<std::chrono::hours>(now - ftime).count() / 24;
            if (age >= maxLogAgeDays) {
                fs::remove(entry.path());
            }
        }
    }

    std::vector<std::string> releases = config["RELEASES"].as<std::vector<std::string>>();

    for (const auto& release : releases) {
        std::time_t now_c = std::time(nullptr);
        char timestamp[20];
        std::strftime(timestamp, sizeof(timestamp), "%Y%m%dT%H%M%S", std::gmtime(&now_c));
        std::string logFileName = LOG_DIR + "/" + std::string(timestamp) + "_" + release + ".log";

        std::ofstream logFile(logFileName, std::ios::app);
        if (!logFile.is_open()) {
            std::cerr << "Error: Unable to open log file: " << logFileName << std::endl;
            continue;
        }

        std::streambuf* coutBuf = std::cout.rdbuf();
        std::streambuf* cerrBuf = std::cerr.rdbuf();
        std::cout.rdbuf(logFile.rdbuf());
        std::cerr.rdbuf(logFile.rdbuf());

        char startTime[20];
        std::strftime(startTime, sizeof(startTime), "%Y-%m-%d %H:%M:%S", std::gmtime(&now_c));
        std::cout << startTime << " - Running Britney for " << release << std::endl;

        processRelease(release, config);

        std::cout.rdbuf(coutBuf);
        std::cerr.rdbuf(cerrBuf);

        logFile.close();
    }

    return 0;
}

void processRelease(const std::string& RELEASE, const YAML::Node& config) {
    std::string MAIN_ARCHIVE = config["MAIN_ARCHIVE"].as<std::string>();
    std::string PORTS_ARCHIVE = config["PORTS_ARCHIVE"].as<std::string>();
    std::string LP_TEAM = config["LP_TEAM"].as<std::string>();
    std::string SOURCE_PPA = config["SOURCE_PPA"].as<std::string>();
    std::string DEST_PPA = config["DEST_PPA"].as<std::string>();
    std::string BRITNEY_CONF = config["BRITNEY_CONF"].as<std::string>();
    std::string BRITNEY_CACHE = config["BRITNEY_CACHE"].as<std::string>();
    std::string BRITNEY_DATADIR = config["BRITNEY_DATADIR"].as<std::string>();
    std::string BRITNEY_OUTDIR = config["BRITNEY_OUTDIR"].as<std::string>();
    std::string BRITNEY_PUBLIC_OUTDIR = config["BRITNEY_PUBLIC_OUTDIR"].as<std::string>();
    std::string BRITNEY_HINTDIR = config["BRITNEY_HINTDIR"].as<std::string>();
    std::string BRITNEY_LOC = config["BRITNEY_LOC"].as<std::string>();

    std::vector<std::string> ARCHES = config["ARCHES"].as<std::vector<std::string>>();
    std::vector<std::string> PORTS_ARCHES = config["PORTS_ARCHES"].as<std::vector<std::string>>();

    std::string SOURCE_PPA_URL = "https://ppa.launchpadcontent.net/" + LP_TEAM + "/" + SOURCE_PPA + "/ubuntu/dists/" + RELEASE + "/main";
    std::string DEST_PPA_URL = "https://ppa.launchpadcontent.net/" + LP_TEAM + "/" + DEST_PPA + "/ubuntu/dists/" + RELEASE + "/main";

    int pendingResult = check_pending_packages(RELEASE);
    if (pendingResult != 0) {
        std::cerr << "Error: pending-packages (now integrated check) failed for release " << RELEASE << std::endl;
        return;
    }

    std::cout << "Refreshing package indexes..." << std::endl;

    std::vector<std::thread> threads;
    std::mutex logMutex;

    std::vector<std::string> pockets = {RELEASE, RELEASE + "-updates"};
    std::vector<std::string> components = {"main", "restricted", "universe", "multiverse"};

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
            {
                std::string url = MAIN_ARCHIVE + pocket + "/" + component + "/source/Sources.gz";
                threads.emplace_back(refresh, url, pocket, BRITNEY_CACHE, std::ref(logMutex));
            }
        }
    }

    {
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
    }

    {
        std::string pocket = SOURCE_PPA + "-" + RELEASE;
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
    }

    for (auto& th : threads) {
        th.join();
    }

    pid_t pid = getpid();
    std::string logPattern = std::to_string(pid) + "-wget-log";

    for (auto& p : fs::recursive_directory_iterator(BRITNEY_CACHE)) {
        if (p.is_regular_file()) {
            std::string filename = p.path().filename().string();
            if (filename.find(logPattern) != std::string::npos) {
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

    std::time_t now_c = std::time(nullptr);
    char timestamp[20];
    std::strftime(timestamp, sizeof(timestamp), "%Y%m%dT%H%M%S", std::gmtime(&now_c));
    fs::create_directories(fs::path(BRITNEY_OUTDIR) / timestamp);

    std::string DEST = BRITNEY_DATADIR + RELEASE + "-proposed";
    fs::create_directories(DEST);
    fs::create_directories(fs::path(BRITNEY_DATADIR) / (RELEASE + "-proposed") / "state");
    writeFile(fs::path(BRITNEY_DATADIR) / (RELEASE + "-proposed") / "state" / "age-policy-dates", "");

    fs::remove(fs::path(DEST) / "Hints");
    fs::create_symlink(BRITNEY_HINTDIR, fs::path(DEST) / "Hints");

    {
        std::string sourcesContent;
        for (auto& p : fs::recursive_directory_iterator(BRITNEY_CACHE + SOURCE_PPA + "-" + RELEASE)) {
            if (p.path().filename() == "Sources.gz") {
                sourcesContent += decompressGzip(p.path());
            }
        }
        writeFile(fs::path(DEST) / "Sources", sourcesContent);

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
    }

    {
        DEST = BRITNEY_DATADIR + RELEASE;
        fs::create_directories(DEST);
        fs::create_directories(fs::path(BRITNEY_DATADIR) / RELEASE / "state");
        writeFile(fs::path(BRITNEY_DATADIR) / RELEASE / "state" / "age-policy-dates", "");

        fs::remove(fs::path(DEST) / "Hints");
        fs::create_symlink(BRITNEY_HINTDIR, fs::path(DEST) / "Hints");

        {
            std::string sourcesContent;
            for (auto& p : fs::recursive_directory_iterator(BRITNEY_CACHE)) {
                if (p.path().filename() == "Sources.gz" && p.path().string().find(RELEASE) != std::string::npos) {
                    sourcesContent += decompressGzip(p.path());
                }
            }
            writeFile(fs::path(DEST) / "Sources", sourcesContent);
            regexReplaceInFile(fs::path(DEST) / "Sources", "Section: universe/", "Section: ");
        }

        for (const auto& arch : ARCHES) {
            std::string packagesContent;
            for (auto& p : fs::recursive_directory_iterator(BRITNEY_CACHE)) {
                if (p.path().filename() == "Packages.gz" && p.path().string().find(RELEASE) != std::string::npos && p.path().parent_path().string().find("binary-" + arch) != std::string::npos) {
                    packagesContent += decompressGzip(p.path());
                }
            }
            fs::path packagesFilePath = fs::path(DEST) / ("Packages_" + arch);
            writeFile(packagesFilePath, packagesContent);
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
            regexReplaceInFile(packagesFilePath, "Section: universe/", "Section: ");
        }

        writeFile(fs::path(DEST) / "Blocks", "");
        writeFile(fs::path(BRITNEY_DATADIR) / (SOURCE_PPA + "-" + RELEASE) / "Dates", "");
    }

    {
        std::string configContent = readFile(BRITNEY_CONF);
        configContent = std::regex_replace(configContent, std::regex("%\\{SERIES\\}"), RELEASE);
        writeFile("britney.conf", configContent);
    }

    std::cout << "Running britney..." << std::endl;
    std::string britneyCmd = BRITNEY_LOC + " -v --config britney.conf --series " + RELEASE;
    int britneyResult = executeAndLog(britneyCmd);
    if (britneyResult != 0) {
        std::cerr << "Error: Britney execution failed for release " << RELEASE << std::endl;
        return;
    }

    std::cout << "Syncing output to frontend..." << std::endl;
    fs::copy(BRITNEY_OUTDIR, BRITNEY_PUBLIC_OUTDIR, fs::copy_options::recursive | fs::copy_options::overwrite_existing);
    fs::remove_all(BRITNEY_OUTDIR);

    std::cout << "Moving packages..." << std::endl;
    {
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

void refresh(const std::string& url, const std::string& pocket, const std::string& britneyCache, std::mutex& logMutex) {
    fs::path urlPath(url);
    std::string lastTwoComponents = urlPath.parent_path().parent_path().filename().string() + "/" + urlPath.parent_path().filename().string();
    fs::path dir = fs::path(britneyCache) / pocket / lastTwoComponents;

    fs::create_directories(dir);

    auto now = fs::file_time_type::clock::now();
    fs::last_write_time(britneyCache, now);
    fs::last_write_time(fs::path(britneyCache) / pocket, now);
    fs::last_write_time(dir.parent_path(), now);
    fs::last_write_time(dir, now);

    pid_t pid = getpid();
    fs::path logFilePath = dir / (std::to_string(pid) + "-wget-log");

    fs::path outputPath = dir / urlPath.filename();

    downloadFileWithTimestamping(url, outputPath, logFilePath, logMutex);
}
