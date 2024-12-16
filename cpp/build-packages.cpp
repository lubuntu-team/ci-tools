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
#include "update-maintainer-lib.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <regex>
#include <map>
#include <optional>
#include <thread>
#include <future>
#include <chrono>
#include <algorithm>
#include <stdexcept>
#include <unordered_set>
#include <iterator>
#include <yaml-cpp/yaml.h>
#include <ctime>
#include <numeric>
#include <semaphore>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

#include <git2.h>

namespace fs = std::filesystem;

// Limit concurrency to 5, ensuring at most 5 directories in /tmp at a time
static std::counting_semaphore<5> semaphore(5);

// Mutex to protect access to the repo_mutexes map
static std::mutex repo_map_mutex;

// Map to hold mutexes for each repository path
static std::unordered_map<fs::path, std::mutex> repo_mutexes;

static std::mutex& get_repo_mutex(const fs::path& repo_path) {
    std::lock_guard<std::mutex> lock(repo_map_mutex);
    return repo_mutexes[repo_path];
}

// Mutex and vector to store dput futures
static std::mutex dput_futures_mutex;
static std::vector<std::future<void>> dput_futures;

static const std::string BASE_DIR = "/srv/lubuntu-ci/repos";
static const std::string DEBFULLNAME = "Lugito";
static const std::string DEBEMAIL = "info@lubuntu.me";
static const std::string OUTPUT_DIR = BASE_DIR + "/build_output";
static const std::vector<std::string> SUPPRESSED_LINTIAN_TAGS = {
    "orig-tarball-missing-upstream-signature",
    "package-has-long-file-name",
    "adopted-extended-field"
};
static const std::string BASE_OUTPUT_DIR = "/srv/lubuntu-ci/output";
static const std::string LOG_DIR = BASE_OUTPUT_DIR + "/logs/source_builds";
static std::string BASE_LINTIAN_DIR;
static const std::string REAL_LINTIAN_DIR = BASE_OUTPUT_DIR + "/lintian";
static std::string urgency_level_override = "low";
static int worker_count = 5;

static bool verbose = false;
static std::ofstream log_file_stream;

static std::string get_current_utc_time() {
    auto now = std::time(nullptr);
    std::tm tm_utc;
    gmtime_r(&now, &tm_utc);
    char buf[20];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_utc);
    return std::string(buf);
}

static void log_all(const std::string &level, const std::string &msg, bool is_error=false) {
    std::string timestamp = get_current_utc_time();
    std::string full_msg = "[" + timestamp + "] [" + level + "] " + msg + "\n";

    if (is_error) {
        std::cerr << full_msg;
    } else if (level != "VERBOSE") {
        std::cout << full_msg;
    }

    if (log_file_stream.is_open()) {
        log_file_stream << full_msg;
        log_file_stream.flush();
    }
}

static void log_info(const std::string &msg) {
    log_all("INFO", msg);
}

static void log_warning(const std::string &msg) {
    log_all("WARN", msg, false);
}

static void log_error(const std::string &msg) {
    log_all("ERROR", msg, true);
}

static void log_verbose(const std::string &msg) {
    if (verbose) {
        log_all("VERBOSE", msg);
    }
}

static void print_help(const std::string &prog_name) {
    std::cout << "Usage: " << prog_name << " [OPTIONS] <config_path>\n"
              << "Options:\n"
              << "  --skip-dput           Skip uploading changes with dput.\n"
              << "  --skip-cleanup        Skip cleaning up the output directory after execution.\n"
              << "  --urgency-level=LEVEL Set the urgency level (default: low).\n"
              << "  --workers=N           Set the number of worker threads (default: 5).\n"
              << "  --verbose, -v         Enable verbose logging.\n"
              << "  --help, -h            Display this help message.\n";
}

static void run_command_silent_on_success(const std::vector<std::string> &cmd, const std::optional<fs::path> &cwd = std::nullopt) {
    std::string command_str = std::accumulate(cmd.begin(), cmd.end(), std::string(),
        [](const std::string &a, const std::string &b) -> std::string { return a + (a.empty() ? "" : " ") + b; });

    log_info("Running command: " + command_str);
    if(cwd) {
        log_info("Executing in directory: " + cwd->string());
    }

    std::string exec_cmd = command_str;
    if(cwd) exec_cmd = "cd " + cwd->string() + " && " + exec_cmd;

    FILE* pipe = popen(exec_cmd.c_str(), "r");
    if(!pipe) {
        log_error("Failed to run command: " + command_str);
        throw std::runtime_error("Command failed to start");
    }
    std::stringstream ss;
    {
        char buffer[256];
        while(fgets(buffer, sizeof(buffer), pipe)) {
            ss << buffer;
        }
    }
    int ret = pclose(pipe);
    if (ret != 0) {
        log_error("Command failed with code " + std::to_string(ret) + ": " + command_str);
        log_error("Output:\n" + ss.str());
        throw std::runtime_error("Command execution failed");
    } else {
        log_verbose("Command executed successfully: " + command_str);
    }
}

static void git_init_once() {
    static std::once_flag flag;
    std::call_once(flag, [](){
        log_info("Initializing libgit2");
        git_libgit2_init();
        log_verbose("libgit2 initialized");
    });
}

static void git_fetch_and_checkout(const fs::path &repo_path, const std::string &repo_url, const std::optional<std::string> &branch) {
    log_info("Fetching and checking out repository: " + repo_url + " into " + repo_path.string());
    git_init_once();
    git_repository* repo = nullptr;
    bool need_clone = false;

    if(fs::exists(repo_path)) {
        log_verbose("Repository path exists. Attempting to open repository.");
        int err = git_repository_open(&repo, repo_path.string().c_str());
        if(err < 0) {
            log_warning("Cannot open repo at " + repo_path.string() + ", recloning.");
            fs::remove_all(repo_path);
            need_clone = true;
        } else {
            log_verbose("Repository opened successfully.");
        }
    } else {
        log_verbose("Repository path does not exist. Cloning required.");
        need_clone = true;
    }

    if(!need_clone && repo != nullptr) {
        git_remote* remote = nullptr;
        int err = git_remote_lookup(&remote, repo, "origin");
        if(err < 0) {
            log_warning("No origin remote found. Recloning.");
            git_repository_free(repo);
            fs::remove_all(repo_path);
            need_clone = true;
        } else {
            const char* url = git_remote_url(remote);
            if(!url || repo_url != url) {
                log_warning("Remote URL differs. Recloning.");
                git_remote_free(remote);
                git_repository_free(repo);
                fs::remove_all(repo_path);
                need_clone = true;
            } else {
                log_verbose("Remote URL matches. Fetching latest changes.");
                git_remote_free(remote);
                git_remote* origin = nullptr;
                git_remote_lookup(&origin, repo, "origin");
                git_fetch_options fetch_opts = GIT_FETCH_OPTIONS_INIT;
                git_remote_fetch(origin, nullptr, &fetch_opts, nullptr);
                git_remote_free(origin);
                log_verbose("Fetch completed.");

                if(branch) {
                    git_reference* ref = nullptr;
                    std::string fullbranch = "refs/remotes/origin/" + *branch;
                    if(git_reference_lookup(&ref, repo, fullbranch.c_str()) == 0) {
                        git_object* target = nullptr;
                        git_reference_peel(&target, ref, GIT_OBJECT_COMMIT);
                        git_checkout_options co_opts = GIT_CHECKOUT_OPTIONS_INIT;
                        co_opts.checkout_strategy = GIT_CHECKOUT_FORCE;
                        git_checkout_tree(repo, target, &co_opts);
                        git_reference_free(ref);
                        git_repository_set_head_detached(repo, git_object_id(target));
                        git_object_free(target);
                        log_info("Checked out branch: " + *branch);
                    } else {
                        log_warning("Branch " + *branch + " not found, recloning.");
                        git_repository_free(repo);
                        fs::remove_all(repo_path);
                        need_clone = true;
                    }
                }
                git_repository_free(repo);
            }
        }
    }

    if(need_clone) {
        log_info("Cloning repository from " + repo_url + " to " + repo_path.string());
        git_clone_options clone_opts = GIT_CLONE_OPTIONS_INIT;
        git_checkout_options co_opts = GIT_CHECKOUT_OPTIONS_INIT;
        co_opts.checkout_strategy = GIT_CHECKOUT_FORCE;
        clone_opts.checkout_opts = co_opts;
        git_repository* newrepo = nullptr;
        int err = git_clone(&newrepo, repo_url.c_str(), repo_path.string().c_str(), &clone_opts);
        if(err < 0) {
            const git_error* e = git_error_last();
            log_error(std::string("Git clone failed: ") + (e ? e->message : "unknown error"));
            throw std::runtime_error("Git clone failed");
        }
        log_info("Repository cloned successfully.");

        if(branch) {
            git_reference* ref = nullptr;
            std::string fullbranch = "refs/remotes/origin/" + *branch;
            if(git_reference_lookup(&ref, newrepo, fullbranch.c_str()) == 0) {
                git_object* target = nullptr;
                git_reference_peel(&target, ref, GIT_OBJECT_COMMIT);
                git_checkout_options co_opts_clone = GIT_CHECKOUT_OPTIONS_INIT;
                co_opts_clone.checkout_strategy = GIT_CHECKOUT_FORCE;
                git_checkout_tree(newrepo, target, &co_opts_clone);
                git_reference_free(ref);
                git_repository_set_head_detached(newrepo, git_object_id(target));
                git_object_free(target);
                log_info("Checked out branch: " + *branch + " after clone.");
            } else {
                log_warning("Git checkout of branch " + *branch + " failed after clone.");
                git_repository_free(newrepo);
                throw std::runtime_error("Branch checkout failed");
            }
        }
        git_repository_free(newrepo);
    }
    log_verbose("Finished fetching and checking out repository: " + repo_path.string());
}

static YAML::Node load_config(const fs::path &config_path) {
    log_info("Loading configuration from " + config_path.string());
    YAML::Node config = YAML::LoadFile(config_path.string());
    if (!config["packages"] || !config["releases"]) {
        log_error("Config file missing 'packages' or 'releases' sections.");
        throw std::runtime_error("Config file must contain 'packages' and 'releases' sections.");
    }
    log_verbose("Configuration loaded successfully.");
    return config;
}

static void publish_lintian() {
    log_info("Publishing Lintian results.");
    if(!BASE_LINTIAN_DIR.empty() && fs::exists(BASE_LINTIAN_DIR)) {
        for (auto &p : fs::recursive_directory_iterator(BASE_LINTIAN_DIR)) {
            if (fs::is_regular_file(p)) {
                fs::path rel = fs::relative(p.path(), BASE_LINTIAN_DIR);
                fs::path dest = fs::path(REAL_LINTIAN_DIR) / rel;
                fs::create_directories(dest.parent_path());
                std::error_code ec;
                fs::copy_file(p.path(), dest, fs::copy_options::overwrite_existing, ec);
                if(ec) {
                    log_error("Failed to copy Lintian file: " + p.path().string() + " to " + dest.string() + ". Error: " + ec.message());
                } else {
                    log_verbose("Copied Lintian file: " + p.path().string() + " to " + dest.string());
                }
            }
        }
        fs::remove_all(BASE_LINTIAN_DIR);
        log_info("Removed temporary Lintian directory: " + BASE_LINTIAN_DIR);
    } else {
        log_verbose("No Lintian directory to publish.");
    }
}

static std::vector<std::string> get_exclusions(const fs::path &packaging) {
    log_verbose("Retrieving exclusions from: " + packaging.string());
    std::vector<std::string> exclusions;
    fs::path cpr = packaging / "debian" / "copyright";
    if(!fs::exists(cpr)) {
        log_verbose("No copyright file found.");
        return exclusions;
    }

    std::ifstream f(cpr);
    if(!f) {
        log_warning("Failed to open copyright file.");
        return exclusions;
    }
    std::string line;
    bool found = false;
    while(std::getline(f, line)) {
        if (line.find("Files-Excluded:") != std::string::npos) {
            log_verbose("Found 'Files-Excluded' in copyright.");
            size_t pos = line.find(':');
            if(pos != std::string::npos) {
                std::string excl = line.substr(pos + 1);
                std::istringstream iss(excl);
                std::string token;
                while(iss >> token) {
                    exclusions.push_back(token);
                    log_verbose("Exclusion added: " + token);
                }
            }
            found = true;
            break;
        }
    }
    if(!found) {
        log_verbose("'Files-Excluded' not found in copyright.");
    }
    return exclusions;
}

static void run_source_lintian(const std::string &name, const fs::path &source_path) {
    log_info("Running Lintian for package: " + name);
    fs::path temp_file = fs::temp_directory_path() / ("lintian_suppress_" + name + ".txt");
    {
        std::ofstream of(temp_file);
        for (auto &tag: SUPPRESSED_LINTIAN_TAGS) {
            of << tag << "\n";
        }
    }
    log_verbose("Created Lintian suppression file: " + temp_file.string());
    std::string cmd = "lintian -EvIL +pedantic --suppress-tags-from-file " + temp_file.string() + " " + source_path.string() + " 2>&1";
    FILE* pipe = popen(cmd.c_str(), "r");
    std::stringstream ss;
    if(pipe) {
        char buffer[256];
        while(fgets(buffer, sizeof(buffer), pipe)) {
            ss << buffer;
        }
        int ret = pclose(pipe);
        fs::remove(temp_file);
        log_verbose("Lintian command exited with code: " + std::to_string(ret));
        if(ret != 0) {
            log_error("Lintian reported issues for " + name + ":\n" + ss.str());
            if(!ss.str().empty()) {
                fs::path pkgdir = fs::path(BASE_LINTIAN_DIR) / name;
                fs::create_directories(pkgdir);
                std::ofstream out(pkgdir / "source.txt", std::ios::app);
                out << ss.str() << "\n";
            }
        } else {
            if(!ss.str().empty()) {
                fs::path pkgdir = fs::path(BASE_LINTIAN_DIR) / name;
                fs::create_directories(pkgdir);
                std::ofstream out(pkgdir / "source.txt", std::ios::app);
                out << ss.str() << "\n";
            }
        }
    } else {
        fs::remove(temp_file);
        log_error("Failed to run Lintian for package: " + name);
    }
    log_verbose("Completed Lintian run for package: " + name);
}

static void dput_source(const std::string &name, const std::string &upload_target, const std::vector<std::string> &changes_files, const std::vector<std::string> &devel_changes_files) {
    log_info("Uploading changes for package: " + name + " to " + upload_target);
    if(!changes_files.empty()) {
        std::string hr_changes;
        for(auto &c: changes_files) hr_changes += c + " ";
        log_verbose("Changes files: " + hr_changes);
        std::vector<std::string> cmd = {"dput", upload_target};
        for(auto &c: changes_files) cmd.push_back(c);
        try {
            run_command_silent_on_success(cmd, OUTPUT_DIR);
            log_info("Successfully uploaded changes for package: " + name);
            for(auto &file: devel_changes_files) {
                if(!file.empty()) {
                    run_source_lintian(name, file);
                }
            }
        } catch (...) {
            log_error("Failed to upload changes for package: " + name);
        }
    } else {
        log_warning("No changes files to upload for package: " + name);
    }
}

static void update_changelog(const fs::path &packaging_dir, const std::string &release, const std::string &version_with_epoch) {
    std::string name = packaging_dir.filename().string();
    log_info("Updating changelog for " + name + " to version " + version_with_epoch + "-0ubuntu1~ppa1");
    try {
        run_command_silent_on_success({"git", "checkout", "debian/changelog"}, packaging_dir);
        log_verbose("Checked out debian/changelog for " + name);
    } catch (const std::exception &e) {
        log_error("Failed to checkout debian/changelog for " + name + ": " + e.what());
        throw;
    }
    std::vector<std::string> cmd = {
        "dch", "--distribution", release, "--package", name, "--newversion", version_with_epoch + "-0ubuntu1~ppa1",
        "--urgency", urgency_level_override, "CI upload."
    };
    run_command_silent_on_success(cmd, packaging_dir);
    log_info("Changelog updated for " + name);
}

static std::string build_package(const fs::path &packaging_dir, const std::map<std::string, std::string> &env_vars, bool large) {
    // Acquire the semaphore here so that each build only happens if there's capacity.
    // This ensures we never have more than 5 /tmp dirs at once.
    semaphore.acquire();
    std::string name = packaging_dir.filename().string();
    log_info("Building source package for " + name);
    fs::path temp_dir;
    std::error_code ec;

    // If anything fails, we still want to release the semaphore and clean up.
    // We'll use a scope guard pattern here.
    auto cleanup = [&]() {
        if(!temp_dir.empty()) {
            fs::remove_all(temp_dir, ec);
            if(ec) {
                log_warning("Failed to remove temporary directory: " + temp_dir.string() + " Error: " + ec.message());
            } else {
                log_verbose("Removed temporary build directory: " + temp_dir.string());
            }
        }
        semaphore.release();
    };

    try {
        if(large) {
            temp_dir = fs::path(OUTPUT_DIR) / (".tmp_" + name + "_" + env_vars.at("VERSION"));
            fs::create_directories(temp_dir);
        } else {
            temp_dir = fs::temp_directory_path() / ("tmp_build_" + name + "_" + env_vars.at("VERSION"));
            fs::create_directories(temp_dir);
        }
        log_verbose("Temporary packaging directory created at: " + temp_dir.string());

        fs::path temp_packaging_dir = temp_dir / name;
        fs::create_directories(temp_packaging_dir, ec);
        if(ec) {
            log_error("Failed to create temporary packaging directory: " + temp_packaging_dir.string() + " Error: " + ec.message());
            throw std::runtime_error("Temporary packaging directory creation failed");
        }

        fs::copy(packaging_dir / "debian", temp_packaging_dir / "debian", fs::copy_options::recursive, ec);
        if(ec) {
            log_error("Failed to copy debian directory: " + ec.message());
            throw std::runtime_error("Failed to copy debian directory");
        }

        std::string tarball_name = name + "_" + env_vars.at("VERSION") + ".orig.tar.gz";
        fs::path tarball_source = fs::path(BASE_DIR) / (name + "_MAIN.orig.tar.gz");
        fs::path tarball_dest = temp_dir / tarball_name;
        fs::copy_file(tarball_source, tarball_dest, fs::copy_options::overwrite_existing, ec);
        if(ec) {
            log_error("Failed to copy tarball: " + ec.message());
            throw std::runtime_error("Failed to copy tarball");
        }

        for (auto &e: env_vars) {
            setenv(e.first.c_str(), e.second.c_str(), 1);
            log_verbose("Set environment variable: " + e.first + " = " + e.second);
        }

        std::vector<std::string> cmd_build = {"debuild", "--no-lintian", "-S", "-d", "-sa", "-nc"};
        run_command_silent_on_success(cmd_build, temp_packaging_dir);

        run_command_silent_on_success({"git", "checkout", "debian/changelog"}, packaging_dir);
        log_info("Built package for " + name);

        std::string pattern = name + "_" + env_vars.at("VERSION");
        std::string changes_file;
        for(auto &entry: fs::directory_iterator(temp_dir)) {
            std::string fname = entry.path().filename().string();
            if(fname.rfind(pattern, 0) == 0) {
                fs::path dest = fs::path(OUTPUT_DIR) / fname;
                fs::copy_file(entry.path(), dest, fs::copy_options::overwrite_existing, ec);
                if(!ec) {
                    log_verbose("Copied built package " + fname + " to " + OUTPUT_DIR);
                }
            }
        }

        for(auto &entry : fs::directory_iterator(OUTPUT_DIR)) {
            std::string fname = entry.path().filename().string();
            if(fname.rfind(name + "_" + env_vars.at("VERSION"), 0) == 0 && fname.ends_with("_source.changes")) {
                changes_file = entry.path().string();
                log_info("Found changes file: " + changes_file);
            }
        }

        if(changes_file.empty()) {
            log_error("No changes file found after build for package: " + name);
            throw std::runtime_error("Changes file not found");
        }

        log_info("Built package successfully, changes file: " + changes_file);

        cleanup();
        return changes_file;
    } catch(...) {
        cleanup();
        throw;
    }
}

static void process_package(const YAML::Node &pkg, const YAML::Node &releases) {
    std::string name = pkg["name"] ? pkg["name"].as<std::string>() : "";
    std::string upload_target = pkg["upload_target"] ? pkg["upload_target"].as<std::string>() : "ppa:lubuntu-ci/unstable-ci-proposed";
    if(name.empty()) {
        log_warning("Skipping package due to missing name.");
        return;
    }
    log_info("Processing package: " + name);

    fs::path packaging_destination = fs::path(BASE_DIR) / name;
    fs::path changelog_path = packaging_destination / "debian" / "changelog";
    std::string version = "";

    std::string upstream_url = pkg["upstream_url"] ? pkg["upstream_url"].as<std::string>() : ("https://github.com/lxqt/" + name + ".git");
    fs::path upstream_destination = fs::path(BASE_DIR) / ("upstream-" + name);
    std::optional<std::string> packaging_branch = std::nullopt;
    if(pkg["packaging_branch"] && pkg["packaging_branch"].IsScalar()) {
        packaging_branch = pkg["packaging_branch"].as<std::string>();
    } else if (releases.size() > 0) {
        packaging_branch = "ubuntu/" + releases[0].as<std::string>();
    }
    std::string packaging_url = pkg["packaging_url"] ? pkg["packaging_url"].as<std::string>() : ("https://git.lubuntu.me/Lubuntu/" + name + "-packaging.git");
    fs::path packaging_repo = packaging_destination;

    std::mutex& upstream_mutex = get_repo_mutex(upstream_destination);
    std::mutex& packaging_mutex = get_repo_mutex(packaging_repo);

    std::scoped_lock lock(upstream_mutex, packaging_mutex);

    git_fetch_and_checkout(upstream_destination, upstream_url, std::nullopt);
    git_fetch_and_checkout(packaging_repo, packaging_url, packaging_branch);

    try {
        log_info("Updating maintainer for package: " + name);
        update_maintainer((packaging_destination / "debian").string(), false);
        log_info("Maintainer updated for package: " + name);
    } catch(std::exception &e) {
        log_warning("update_maintainer error for " + name + ": " + std::string(e.what()));
    }

    auto exclusions = get_exclusions(packaging_destination);
    log_info("Creating tarball for package: " + name);
    create_tarball(name, upstream_destination, exclusions);
    log_info("Tarball created for package: " + name);

    version = parse_version(changelog_path);

    bool large = pkg["large"] ? pkg["large"].as<bool>() : false;
    if(large) {
        log_info("Package " + name + " is marked as large.");
    }

    std::map<std::string, std::string> env_map;
    env_map["DEBFULLNAME"] = DEBFULLNAME;
    env_map["DEBEMAIL"] = DEBEMAIL;

    std::string epoch;
    std::string version_no_epoch = version;
    if(auto pos = version.find(':'); pos != std::string::npos) {
        epoch = version.substr(0, pos);
        version_no_epoch = version.substr(pos + 1);
        log_verbose("Package " + name + " has epoch: " + epoch);
    }
    env_map["VERSION"] = version_no_epoch;

    std::vector<std::string> changes_files;
    std::vector<std::string> devel_changes_files;
    for(auto rel : releases) {
        std::string release = rel.as<std::string>();
        log_info("Building " + name + " for release: " + release);

        std::string release_version_no_epoch = version_no_epoch + "~" + release;
        std::string version_for_dch = epoch.empty() ? release_version_no_epoch : (epoch + ":" + release_version_no_epoch);
        env_map["UPLOAD_TARGET"] = upload_target;

        update_changelog(packaging_destination, release, version_for_dch);
        env_map["VERSION"] = release_version_no_epoch;

        try {
            std::string changes_file = build_package(packaging_destination, env_map, large);
            if(!changes_file.empty()) {
                changes_files.push_back(changes_file);
                if(rel == releases[0]) {
                    devel_changes_files.push_back(changes_file);
                } else {
                    devel_changes_files.push_back("");
                }
            }
        } catch(std::exception &e) {
            log_error("Error building package '" + name + "' for release '" + release + "': " + std::string(e.what()));
        }
    }

    fs::path main_tarball = fs::path(BASE_DIR) / (name + "_MAIN.orig.tar.gz");
    fs::remove(main_tarball);
    log_verbose("Removed main orig tarball for package: " + name);

    if(!changes_files.empty() && !upload_target.empty()) {
        std::vector<std::string> dput_changes = changes_files;
        std::vector<std::string> dput_devel_changes = devel_changes_files;
        auto fut = std::async(std::launch::async, [name, upload_target, dput_changes, dput_devel_changes]() {
            dput_source(name, upload_target, dput_changes, dput_devel_changes);
        });
        {
            std::lock_guard<std::mutex> lock(dput_futures_mutex);
            dput_futures.emplace_back(std::move(fut));
        }
    } else {
        log_warning("No changes files to upload for package: " + name);
    }
}

static void prepare_package(const YAML::Node &pkg, const YAML::Node &releases) {
    try {
        process_package(pkg, releases);
    } catch(const std::exception &e) {
        log_error(std::string("Exception in processing package: ") + e.what());
    }
}

int main(int argc, char** argv) {
    std::string prog_name = fs::path(argv[0]).filename().string();
    for(int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if(arg == "--help" || arg == "-h") {
            print_help(prog_name);
            return 0;
        }
        if(arg == "--verbose" || arg == "-v") {
            verbose = true;
            for(int j = i; j < argc - 1; j++) {
                argv[j] = argv[j+1];
            }
            argc--;
            i--;
            continue;
        }
    }

    log_info("Script started.");
    fs::create_directories(LOG_DIR);
    log_info("Ensured log directory exists: " + LOG_DIR);
    fs::create_directories(OUTPUT_DIR);
    log_info("Ensured output directory exists: " + OUTPUT_DIR);

    auto now = std::time(nullptr);
    std::tm tm;
    gmtime_r(&now, &tm);
    char buf_time[20];
    std::strftime(buf_time, sizeof(buf_time), "%Y%m%dT%H%M%S", &tm);
    std::string current_time = buf_time;

    std::string uuid_part = current_time.substr(0,10);
    BASE_LINTIAN_DIR = BASE_OUTPUT_DIR + "/.lintian.tmp." + uuid_part;
    fs::create_directories(BASE_LINTIAN_DIR);
    log_info("Created Lintian temporary directory: " + BASE_LINTIAN_DIR);

    fs::path log_file = fs::path(LOG_DIR) / (current_time + ".log");
    log_info("Opening log file: " + log_file.string());
    log_file_stream.open(log_file);
    if(!log_file_stream.is_open()) {
        std::cerr << "[ERROR] Unable to open log file.\n";
        return 1;
    }
    log_info("Log file opened successfully.");

    bool skip_dput = false;
    bool skip_cleanup = false;
    std::string config_path;
    for(int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        log_info("Processing argument: " + arg);
        if(arg == "--skip-dput") {
            skip_dput = true;
            log_info("Flag set: --skip-dput");
        } else if(arg == "--skip-cleanup") {
            skip_cleanup = true;
            log_info("Flag set: --skip-cleanup");
        } else if(arg.rfind("--urgency-level=", 0) == 0) {
            urgency_level_override = arg.substr(std::string("--urgency-level=").size());
            log_info("Urgency level overridden to: " + urgency_level_override);
        } else if(arg.rfind("--workers=", 0) == 0) {
            worker_count = std::stoi(arg.substr(std::string("--workers=").size()));
            if(worker_count < 1) worker_count = 1;
            log_info("Worker count set to: " + std::to_string(worker_count));
        } else if(config_path.empty()) {
            config_path = arg;
            log_info("Config path set to: " + config_path);
        }
    }

    if(config_path.empty()) {
        log_error("No config file specified.");
        print_help(prog_name);
        return 1;
    }

    setenv("DEBFULLNAME", DEBFULLNAME.c_str(), 1);
    log_info("Set DEBFULLNAME to: " + DEBFULLNAME);
    setenv("DEBEMAIL", DEBEMAIL.c_str(), 1);
    log_info("Set DEBEMAIL to: " + DEBEMAIL);

    YAML::Node config;
    try {
        config = load_config(config_path);
    } catch (std::exception &e) {
        log_error(std::string("Error loading config file: ") + e.what());
        return 1;
    }

    auto packages = config["packages"];
    auto releases = config["releases"];
    log_info("Loaded " + std::to_string(packages.size()) + " packages and " + std::to_string(releases.size()) + " releases from config.");

    fs::current_path(BASE_DIR);
    log_info("Set current working directory to BASE_DIR: " + BASE_DIR);

    std::vector<std::future<void>> futures;
    log_info("Starting package preparation for " + std::to_string(packages.size()) + " packages.");
    for(auto pkg : packages) {
        futures.emplace_back(std::async(std::launch::async, prepare_package, pkg, releases));
    }

    for(auto &fut : futures) {
        try {
            fut.get();
            log_info("Package processed successfully.");
        } catch(std::exception &e) {
            log_error(std::string("Task generated an exception: ") + e.what());
        }
    }

    {
        std::lock_guard<std::mutex> lock(dput_futures_mutex);
        for(auto &fut : dput_futures) {
            try {
                fut.get();
                log_info("Dput upload completed successfully.");
            } catch(std::exception &e) {
                log_error(std::string("Dput upload generated an exception: ") + e.what());
            }
        }
    }

    if(!skip_cleanup) {
        log_info("Cleaning up output directory: " + OUTPUT_DIR);
        fs::remove_all(OUTPUT_DIR);
        log_info("Cleanup completed.");
    } else {
        log_info("Skipping cleanup as per flag.");
    }
    log_info("Publishing Lintian results.");
    publish_lintian();
    log_info("Cleaning old logs.");
    clean_old_logs(fs::path(LOG_DIR));

    log_info("Script completed successfully.");
    return 0;
}
