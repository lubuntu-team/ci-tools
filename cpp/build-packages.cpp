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

#include <git2.h>

namespace fs = std::filesystem;

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

static std::ofstream log_file_stream;

static void log_all(const std::string &msg, bool is_error=false) {
    if (is_error) {
        std::cerr << msg;
    } else {
        std::cout << msg;
    }
    if (log_file_stream.is_open()) {
        log_file_stream << msg;
        log_file_stream.flush();
    }
}

static void log_info(const std::string &msg) {
    log_all("[INFO] " + msg + "\n");
}

static void log_warning(const std::string &msg) {
    log_all("[WARN] " + msg + "\n", false);
}

static void log_error(const std::string &msg) {
    log_all("[ERROR] " + msg + "\n", true);
}

static void run_command_silent_on_success(const std::vector<std::string> &cmd, const std::optional<fs::path> &cwd = std::nullopt) {
    log_info("run_command_silent_on_success called with command: " + std::accumulate(cmd.begin(), cmd.end(), std::string(),
        [](const std::string &a, const std::string &b) -> std::string { return a + (a.length() > 0 ? " " : "") + b; }));
    if(cwd) {
        log_info("Current working directory for command: " + cwd->string());
    } else {
        log_info("No specific working directory for command.");
    }

    std::string full_cmd;
    for (auto &c: cmd) full_cmd += c + " ";
    std::string exec_cmd = full_cmd;
    if(cwd) exec_cmd = "cd " + cwd->string() + " && " + exec_cmd;

    log_info("Executing command: " + exec_cmd);

    FILE* pipe = popen(exec_cmd.c_str(), "r");
    if(!pipe) {
        log_error("Failed to run command: " + full_cmd);
        throw std::runtime_error("Command failed to start");
    }
    std::stringstream ss;
    {
        char buffer[256];
        while(fgets(buffer,256,pipe)) {
            ss << buffer;
        }
    }
    int ret = pclose(pipe);
    log_info("Command executed with return code: " + std::to_string(ret));
    if (ret != 0) {
        log_error("Command failed: " + full_cmd);
        log_error("Output:\n" + ss.str());
        throw std::runtime_error("Command execution failed");
    } else {
        log_info("Command succeeded: " + full_cmd);
    }
}

static void git_init_once() {
    log_info("git_init_once called");
    static std::once_flag flag;
    std::call_once(flag, [](){
        log_info("Initializing libgit2");
        git_libgit2_init();
        log_info("libgit2 initialized");
    });
}

static void git_fetch_and_checkout(const fs::path &repo_path, const std::string &repo_url, const std::optional<std::string> &branch) {
    log_info("git_fetch_and_checkout called with repo_path: " + repo_path.string() + ", repo_url: " + repo_url + ", branch: " + (branch ? *branch : "none"));
    git_init_once();
    git_repository* repo = nullptr;
    bool need_clone = false;
    if(fs::exists(repo_path)) {
        log_info("Repository path exists. Attempting to open repository.");
        int err = git_repository_open(&repo, repo_path.string().c_str());
        if(err<0) {
            log_warning("Cannot open repo at " + repo_path.string() + ", recloning");
            fs::remove_all(repo_path);
            need_clone = true;
        } else {
            log_info("Repository opened successfully.");
        }
    } else {
        log_info("Repository path does not exist. Cloning required.");
        need_clone = true;
    }

    if(!need_clone && repo!=nullptr) {
        log_info("Checking remote 'origin' for repository.");
        git_remote* remote = nullptr;
        int err = git_remote_lookup(&remote, repo, "origin");
        if(err<0) {
            log_warning("No origin remote found. Recloning.");
            git_repository_free(repo);
            fs::remove_all(repo_path);
            need_clone = true;
        } else {
            const char* url = git_remote_url(remote);
            if(!url || repo_url != url) {
                log_info("Remote URL differs (current: " + std::string(url ? url : "null") + "). Removing and recloning.");
                git_remote_free(remote);
                git_repository_free(repo);
                fs::remove_all(repo_path);
                need_clone = true;
            } else {
                log_info("Remote URL matches. Proceeding to fetch.");
                // fetch
                git_remote_free(remote);
                git_remote* origin = nullptr;
                git_remote_lookup(&origin, repo, "origin");
                git_fetch_options fetch_opts = GIT_FETCH_OPTIONS_INIT;
                git_remote_fetch(origin, nullptr, &fetch_opts, nullptr);
                log_info("Fetch completed.");
                git_remote_free(origin);

                if(branch) {
                    log_info("Checking out branch: " + *branch);
                    git_reference* ref = nullptr;
                    std::string fullbranch = "refs/remotes/origin/" + *branch;
                    if(git_reference_lookup(&ref, repo, fullbranch.c_str())==0) {
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
                        log_error("Branch " + *branch + " not found, recloning");
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
        if(err<0) {
            const git_error* e = git_error_last();
            log_error(std::string("Git clone failed: ") + (e ? e->message : "unknown error"));
            throw std::runtime_error("Git clone failed");
        }
        log_info("Repository cloned successfully.");

        if(branch) {
            log_info("Checking out branch after clone: " + *branch);
            git_reference* ref = nullptr;
            std::string fullbranch = "refs/remotes/origin/" + *branch;
            if(git_reference_lookup(&ref, newrepo, fullbranch.c_str())==0) {
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
                log_error("Git checkout of branch " + *branch + " failed after clone.");
                git_repository_free(newrepo);
                throw std::runtime_error("Branch checkout failed");
            }
        }
        git_repository_free(newrepo);
    }
    log_info("git_fetch_and_checkout completed for " + repo_path.string());
}

static YAML::Node load_config(const fs::path &config_path) {
    log_info("Loading configuration from " + config_path.string());
    YAML::Node config = YAML::LoadFile(config_path.string());
    if (!config["packages"] || !config["releases"]) {
        log_error("Config file missing 'packages' or 'releases' sections.");
        throw std::runtime_error("Config file must contain 'packages' and 'releases' sections.");
    }
    log_info("Configuration loaded successfully.");
    return config;
}

static void publish_lintian() {
    log_info("publish_lintian called.");
    if(!BASE_LINTIAN_DIR.empty() && fs::exists(BASE_LINTIAN_DIR)) {
        log_info("Publishing lintian results from " + BASE_LINTIAN_DIR);
        for (auto &p : fs::recursive_directory_iterator(BASE_LINTIAN_DIR)) {
            if (fs::is_regular_file(p)) {
                fs::path rel = fs::relative(p.path(), BASE_LINTIAN_DIR);
                fs::path dest = fs::path(REAL_LINTIAN_DIR) / rel;
                fs::create_directories(dest.parent_path());
                std::error_code ec;
                fs::copy_file(p.path(), dest, fs::copy_options::overwrite_existing, ec);
                if(ec) {
                    log_error("Failed to copy lintian file: " + p.path().string() + " to " + dest.string() + ". Error: " + ec.message());
                } else {
                    log_info("Copied lintian file: " + p.path().string() + " to " + dest.string());
                }
            }
        }
        fs::remove_all(BASE_LINTIAN_DIR);
        log_info("Removed temporary lintian directory: " + BASE_LINTIAN_DIR);
    } else {
        log_info("No lintian directory to publish.");
    }
}

static std::vector<std::string> get_exclusions(const fs::path &packaging) {
    log_info("get_exclusions called for packaging directory: " + packaging.string());
    std::vector<std::string> exclusions;
    fs::path cpr = packaging / "debian" / "copyright";
    if(!fs::exists(cpr)) {
        log_info("No copyright file found at " + cpr.string());
        return exclusions;
    }

    std::ifstream f(cpr);
    if(!f) {
        log_warning("Failed to open copyright file at " + cpr.string());
        return exclusions;
    }
    std::string line;
    bool found = false;
    while(std::getline(f,line)) {
        if (line.find("Files-Excluded:") != std::string::npos) {
            log_info("Found 'Files-Excluded' in copyright.");
            size_t pos=line.find(':');
            if(pos!=std::string::npos) {
                std::string excl = line.substr(pos+1);
                std::istringstream iss(excl);
                std::string token;
                while(iss>>token) {
                    exclusions.push_back(token);
                    log_info("Exclusion added: " + token);
                }
            }
            found = true;
            break;
        }
    }
    if(!found) {
        log_info("'Files-Excluded' not found in copyright.");
    }
    return exclusions;
}

int main(int argc, char** argv) {
    log_info("Script started.");
    fs::create_directories(LOG_DIR);
    log_info("Ensured log directory exists: " + LOG_DIR);
    fs::create_directories(OUTPUT_DIR);
    log_info("Ensured output directory exists: " + OUTPUT_DIR);

    auto now = std::time(nullptr);
    std::tm tm = *std::gmtime(&now);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y%m%dT%H%M%S", &tm);
    std::string current_time = buf;

    std::string uuid_part = current_time.substr(0,8);
    BASE_LINTIAN_DIR = BASE_OUTPUT_DIR + "/.lintian.tmp." + uuid_part;
    fs::create_directories(BASE_LINTIAN_DIR);
    log_info("Created lintian temporary directory: " + BASE_LINTIAN_DIR);

    fs::path log_file = fs::path(LOG_DIR) / (current_time + ".log");
    log_info("Opening log file: " + log_file.string());
    log_file_stream.open(log_file);
    if(!log_file_stream.is_open()) {
        std::cerr<<"[ERROR] Unable to open log file.\n";
        return 1;
    }
    log_info("Log file opened successfully.");

    bool skip_dput = false;
    bool skip_cleanup = false;
    std::string config_path;
    for(int i=1; i<argc; i++) {
        std::string arg=argv[i];
        log_info("Processing command-line argument: " + arg);
        if(arg=="--skip-dput") {
            skip_dput=true;
            log_info("Flag set to skip dput.");
        } else if(arg=="--skip-cleanup") {
            skip_cleanup=true;
            log_info("Flag set to skip cleanup.");
        } else if(arg.rfind("--urgency-level=",0)==0) {
            urgency_level_override = arg.substr(std::string("--urgency-level=").size());
            log_info("Urgency level override set to: " + urgency_level_override);
        } else if(arg.rfind("--workers=",0)==0) {
            worker_count = std::stoi(arg.substr(std::string("--workers=").size()));
            if(worker_count<1) worker_count=1;
            log_info("Worker count set to: " + std::to_string(worker_count));
        } else if(config_path.empty()) {
            config_path = arg;
            log_info("Config path set to: " + config_path);
        }
    }

    if(config_path.empty()) {
        log_error("No config file specified.");
        return 1;
    }

    setenv("DEBFULLNAME", DEBFULLNAME.c_str(),1);
    log_info("Set environment variable DEBFULLNAME to " + DEBFULLNAME);
    setenv("DEBEMAIL", DEBEMAIL.c_str(),1);
    log_info("Set environment variable DEBEMAIL to " + DEBEMAIL);

    YAML::Node config;
    try {
        config = load_config(config_path);
    } catch (std::exception &e) {
        log_error(std::string("Error loading config file: ")+e.what());
        return 1;
    }

    auto packages = config["packages"];
    auto releases = config["releases"];
    log_info("Loaded " + std::to_string(packages.size()) + " packages and " + std::to_string(releases.size()) + " releases from config.");

    fs::current_path(BASE_DIR);
    log_info("Set current working directory to BASE_DIR: " + BASE_DIR);

    auto get_packaging_branch = [&](const YAML::Node &pkg)->std::optional<std::string>{
        log_info("Determining packaging branch for package.");
        if(pkg["packaging_branch"] && pkg["packaging_branch"].IsScalar()) {
            std::string branch = pkg["packaging_branch"].as<std::string>();
            log_info("Packaging branch found in package config: " + branch);
            return branch;
        } else if (releases.size()>0) {
            std::string branch = "ubuntu/" + releases[0].as<std::string>();
            log_info("Defaulting packaging branch to: " + branch);
            return branch;
        }
        log_info("No packaging branch specified.");
        return std::nullopt;
    };

    auto parse_version = [&](const fs::path &changelog_path) -> std::string {
        log_info("Parsing version from changelog: " + changelog_path.string());
        std::ifstream f(changelog_path);
        if(!f) {
            log_error("Changelog not found: " + changelog_path.string());
            throw std::runtime_error("Changelog not found: " + changelog_path.string());
        }
        std::string first_line;
        std::getline(f, first_line);
        size_t start = first_line.find('(');
        size_t end = first_line.find(')');
        if(start==std::string::npos||end==std::string::npos) {
            log_error("Invalid changelog format in " + changelog_path.string());
            throw std::runtime_error("Invalid changelog format");
        }
        std::string version_match = first_line.substr(start+1,end-(start+1));
        log_info("Extracted version string: " + version_match);
        std::string epoch;
        std::string upstream_version = version_match;
        if(auto pos=version_match.find(':'); pos!=std::string::npos) {
            epoch=version_match.substr(0,pos);
            upstream_version=version_match.substr(pos+1);
            log_info("Parsed epoch: " + epoch + ", upstream version: " + upstream_version);
        }
        if(auto pos=upstream_version.find('-'); pos!=std::string::npos) {
            upstream_version=upstream_version.substr(0,pos);
            log_info("Trimmed upstream version to: " + upstream_version);
        }
        std::regex git_regex("(\\+git[0-9]+)?(~[a-z]+)?$");
        upstream_version = std::regex_replace(upstream_version, git_regex, "");
        log_info("Upstream version after regex replacement: " + upstream_version);
        auto t = std::time(nullptr);
        std::tm tm = *std::gmtime(&t);
        char buf_version[32];
        std::strftime(buf_version, sizeof(buf_version), "%Y%m%d%H%M", &tm);
        std::string current_date = buf_version;
        std::string version;
        if(!epoch.empty()) {
            version = epoch + ":" + upstream_version + "+git" + current_date;
        } else {
            version = upstream_version + "+git" + current_date;
        }
        log_info("Final parsed version: " + version);
        return version;
    };

    auto run_source_lintian = [&](const std::string &name, const fs::path &source_path){
        log_info("Running Lintian for package: " + name + " with source path: " + source_path.string());
        fs::path temp_file = fs::temp_directory_path() / ("lintian_suppress_" + name + ".txt");
        {
            std::ofstream of(temp_file);
            for (auto &tag: SUPPRESSED_LINTIAN_TAGS) {
                of<<tag<<"\n";
                log_info("Suppressed Lintian tag added: " + tag);
            }
        }
        std::string cmd = "lintian -EvIL +pedantic --suppress-tags-from-file " + temp_file.string() + " " + source_path.string() + " 2>&1";
        log_info("Executing Lintian command: " + cmd);
        FILE* pipe = popen(cmd.c_str(),"r");
        std::stringstream ss;
        if(pipe) {
            char buffer[256];
            while(fgets(buffer,256,pipe)) {
                ss<<buffer;
            }
            int ret = pclose(pipe);
            log_info("Lintian command exited with code: " + std::to_string(ret));
            fs::remove(temp_file);
            log_info("Removed temporary lintian suppress file: " + temp_file.string());
            if(ret!=0) {
                log_error("Lintian reported issues:\n"+ss.str());
                if(!ss.str().empty()) {
                    fs::path pkgdir = fs::path(BASE_LINTIAN_DIR)/name;
                    fs::create_directories(pkgdir);
                    std::ofstream out(pkgdir/"source.txt",std::ios::app);
                    out<<ss.str()<<"\n";
                    log_info("Logged lintian issues to " + (pkgdir/"source.txt").string());
                }
            } else {
                if(!ss.str().empty()) {
                    fs::path pkgdir = fs::path(BASE_LINTIAN_DIR)/name;
                    fs::create_directories(pkgdir);
                    std::ofstream out(pkgdir/"source.txt",std::ios::app);
                    out<<ss.str()<<"\n";
                    log_info("Logged lintian output to " + (pkgdir/"source.txt").string());
                }
            }
        } else {
            fs::remove(temp_file);
            log_error("Failed to run lintian for package: " + name);
        }
        log_info("Lintian run for " + name + " is complete");
    };

    auto dput_source = [&](const std::string &name, const std::string &upload_target, const std::vector<std::string> &changes_files, const std::vector<std::string> &devel_changes_files){
        log_info("dput_source called for package: " + name + ", upload_target: " + upload_target);
        if(!changes_files.empty()) {
            std::string hr_changes;
            for(auto &c: changes_files) {
                hr_changes += c+" ";
                log_info("Change file to upload: " + c);
            }
            log_info("Uploading " + hr_changes + "to " + upload_target + " using dput");
            std::vector<std::string> cmd = {"dput",upload_target};
            for(auto &c: changes_files) cmd.push_back(c);
            try {
                run_command_silent_on_success(cmd, OUTPUT_DIR);
                log_info("Completed upload of changes to " + upload_target);
                for(auto &file: devel_changes_files) {
                    if(!file.empty()) {
                        log_info("Running Lintian on devel changes file: " + file);
                        run_source_lintian(name,file);
                    }
                }
            } catch (...) {
                log_error("Failed to upload changes for package: " + name);
                // error logged already
            }
        } else {
            log_info("No changes files to upload for package: " + name);
        }
    };

    auto update_changelog = [&](const fs::path &packaging_dir, const std::string &release, const std::string &version_with_epoch){
        std::string name = packaging_dir.filename().string();
        log_info("Updating changelog for " + name + " to version " + version_with_epoch + "-0ubuntu1~ppa1");
        try {
            run_command_silent_on_success({"git","checkout","debian/changelog"}, packaging_dir);
            log_info("Checked out debian/changelog for " + name);
        } catch (const std::exception &e) {
            log_error("Failed to checkout debian/changelog for " + name + ": " + e.what());
            throw;
        }
        std::vector<std::string> cmd={
            "dch","--distribution",release,"--package",name,"--newversion",version_with_epoch+"-0ubuntu1~ppa1","--urgency",urgency_level_override,"CI upload."
        };
        log_info("Running dch command to update changelog for " + name);
        try {
            run_command_silent_on_success(cmd, packaging_dir);
            log_info("Changelog updated successfully for " + name);
        } catch (const std::exception &e) {
            log_error("Failed to update changelog for " + name + ": " + e.what());
            throw;
        }
    };

    auto build_package = [&](const fs::path &packaging_dir, const std::map<std::string,std::string> &env_vars, bool large) -> std::string {
        std::string name = packaging_dir.filename().string();
        log_info("Building source package for " + name);
        fs::path temp_dir;
        if(large) {
            temp_dir = fs::path(OUTPUT_DIR)/(".tmp_"+name+"_"+env_vars.at("VERSION"));
            fs::create_directories(temp_dir);
            log_warning(name+" is quite large and will not fit in /tmp, building at "+temp_dir.string());
        } else {
            temp_dir = fs::temp_directory_path()/("tmp_build_"+name+"_"+env_vars.at("VERSION"));
            fs::create_directories(temp_dir);
            log_info("Temporary build directory created at " + temp_dir.string());
        }

        std::error_code ec;
        fs::path temp_packaging_dir = temp_dir/name;
        fs::create_directories(temp_packaging_dir, ec);
        if(ec) {
            log_error("Failed to create temporary packaging directory: " + temp_packaging_dir.string() + ". Error: " + ec.message());
            throw std::runtime_error("Failed to create temporary packaging directory.");
        }
        log_info("Temporary packaging directory created at " + temp_packaging_dir.string());

        fs::copy(packaging_dir/"debian", temp_packaging_dir/"debian", fs::copy_options::recursive, ec);
        if(ec) {
            log_error("Failed to copy debian directory to temporary packaging directory: " + ec.message());
            throw std::runtime_error("Failed to copy debian directory.");
        }
        log_info("Copied debian directory to temporary packaging directory.");

        std::string tarball_name = name+"_"+env_vars.at("VERSION")+".orig.tar.gz";
        fs::path tarball_source = fs::path(BASE_DIR)/(name+"_MAIN.orig.tar.gz");
        fs::path tarball_dest = temp_dir/tarball_name;
        fs::copy_file(tarball_source, tarball_dest, fs::copy_options::overwrite_existing, ec);
        if(ec) {
            log_error("Failed to copy tarball from " + tarball_source.string() + " to " + tarball_dest.string() + ". Error: " + ec.message());
            throw std::runtime_error("Failed to copy tarball.");
        }
        log_info("Copied tarball to " + tarball_dest.string());

        for (auto &e: env_vars) {
            setenv(e.first.c_str(), e.second.c_str(),1);
            log_info("Set environment variable: " + e.first + " = " + e.second);
        }

        std::vector<std::string> cmd_build={"debuild","--no-lintian","-S","-d","-sa","-nc"};
        log_info("Running debuild command in " + temp_packaging_dir.string());
        try {
            run_command_silent_on_success(cmd_build, temp_packaging_dir);
            run_command_silent_on_success({"git","checkout","debian/changelog"}, packaging_dir);
            log_info("Completed debuild and reset changelog for " + name);
        } catch(...) {
            fs::remove_all(temp_dir, ec);
            log_error("Build failed for " + name + ". Cleaned up temporary directory.");
            throw;
        }

        std::string pattern = name+"_"+env_vars.at("VERSION");
        std::string changes_file;
        for(auto &entry: fs::directory_iterator(temp_dir)) {
            std::string fname=entry.path().filename().string();
            if(fname.rfind(pattern,0)==0) {
                fs::path dest=fs::path(OUTPUT_DIR)/fname;
                fs::copy_file(entry.path(), dest, fs::copy_options::overwrite_existing, ec);
                if(ec) {
                    log_error("Failed to copy built package " + fname + " to " + OUTPUT_DIR + ". Error: " + ec.message());
                } else {
                    log_info("Copied " + fname + " to " + OUTPUT_DIR);
                }
            }
        }

        for(auto &entry : fs::directory_iterator(OUTPUT_DIR)) {
            std::string fname=entry.path().filename().string();
            if(fname.rfind(name+"_"+env_vars.at("VERSION"),0)==0 && fname.ends_with("_source.changes")) {
                changes_file=entry.path().string();
                log_info("Found changes file: " + changes_file);
                break;
            }
        }

        fs::remove_all(temp_dir, ec);
        if(ec) {
            log_warning("Failed to remove temporary directory: " + temp_dir.string() + ". Error: " + ec.message());
        } else {
            log_info("Removed temporary build directory: " + temp_dir.string());
        }

        if(changes_file.empty()) {
            log_error("No changes file found after build for package: " + name);
            throw std::runtime_error("Changes file not found");
        }
        log_info("Built package successfully, changes file: " + changes_file);
        return changes_file;
    };

    auto process_package = [&](const YAML::Node &pkg){
        std::string name = pkg["name"] ? pkg["name"].as<std::string>() : "";
        std::string upload_target = pkg["upload_target"] ? pkg["upload_target"].as<std::string>() : "ppa:lubuntu-ci/unstable-ci-proposed";
        log_info("Processing package: " + name + " with upload target: " + upload_target);
        if(name.empty()) {
            log_warning("Skipping package due to missing name.");
            return;
        }
        fs::path packaging_destination = fs::path(BASE_DIR)/name;
        fs::path changelog_path = packaging_destination/"debian"/"changelog";
        std::string version = parse_version(changelog_path);

        bool large = pkg["large"] ? pkg["large"].as<bool>() : false;
        if(large) {
            log_info("Package " + name + " marked as large.");
        }

        std::vector<std::pair<std::string,std::map<std::string,std::string>>> built_changes;

        std::string epoch;
        std::string version_no_epoch=version;
        if(auto pos=version.find(':');pos!=std::string::npos) {
            epoch=version.substr(0,pos);
            version_no_epoch=version.substr(pos+1);
            log_info("Package " + name + " has epoch: " + epoch);
        }

        for (auto rel : releases) {
            std::string release = rel.as<std::string>();
            log_info("Building " + name + " for release: " + release);

            std::string release_version_no_epoch = version_no_epoch + "~" + release;
            fs::path tarball_source = fs::path(BASE_DIR)/(name+"_MAIN.orig.tar.gz");
            fs::path tarball_dest = fs::path(BASE_DIR)/(name+"_"+release_version_no_epoch+".orig.tar.gz");
            std::error_code ec;
            fs::copy_file(tarball_source, tarball_dest, fs::copy_options::overwrite_existing, ec);
            if(ec) {
                log_error("Failed to copy tarball for " + name + " to " + tarball_dest.string() + ". Error: " + ec.message());
                continue;
            }
            log_info("Copied tarball to " + tarball_dest.string());

            std::string version_for_dch = epoch.empty()? release_version_no_epoch : (epoch+":"+release_version_no_epoch);
            log_info("Version for dch: " + version_for_dch);

            std::map<std::string,std::string> env_map;
            env_map["DEBFULLNAME"]=DEBFULLNAME;
            env_map["DEBEMAIL"]=DEBEMAIL;
            env_map["VERSION"]=release_version_no_epoch;
            env_map["UPLOAD_TARGET"]=upload_target;

            try {
                update_changelog(packaging_destination, release, version_for_dch);
                std::string changes_file = build_package(packaging_destination, env_map, large);
                if(!changes_file.empty()) {
                    built_changes.emplace_back(changes_file, env_map);
                    log_info("Recorded built changes file: " + changes_file);
                }
            } catch(std::exception &e) {
                log_error("Error processing package '"+name+"' for release '"+release+"': "+std::string(e.what()));
            }

            fs::remove(tarball_dest, ec);
            if(ec) {
                log_warning("Failed to remove tarball: " + tarball_dest.string() + ". Error: " + ec.message());
            } else {
                log_info("Removed tarball: " + tarball_dest.string());
            }
        }

        std::vector<std::string> changes_files;
        for(auto &bc: built_changes) {
            fs::path cf(bc.first);
            changes_files.push_back(cf.filename().string());
            log_info("Collected changes file: " + cf.filename().string());
        }

        std::unordered_set<std::string> devel_changes_files;
        if(releases.size()>0) {
            std::string first_release = releases[0].as<std::string>();
            for (auto &f: changes_files) {
                if(f.find("~"+first_release)!=std::string::npos) {
                    devel_changes_files.insert((fs::path(OUTPUT_DIR)/f).string());
                    log_info("Added to devel changes files: " + (fs::path(OUTPUT_DIR)/f).string());
                } else {
                    devel_changes_files.insert(std::string());
                    log_info("Added empty string to devel changes files.");
                }
            }
        }

        if(built_changes.empty()) {
            log_warning("No built changes files for package: " + name);
            return;
        }

        if(getenv("DEBFULLNAME")==nullptr) {
            setenv("DEBFULLNAME",DEBFULLNAME.c_str(),1);
            log_info("Set environment variable DEBFULLNAME for package: " + name);
        }
        if(getenv("DEBEMAIL")==nullptr) {
            setenv("DEBEMAIL",DEBEMAIL.c_str(),1);
            log_info("Set environment variable DEBEMAIL for package: " + name);
        }

        if(skip_dput) {
            log_info("Skipping dput for package: " + name);
            for (auto &file : devel_changes_files) {
                if(!file.empty()) {
                    run_source_lintian(name,file);
                }
            }
        } else {
            std::string real_upload_target = built_changes[0].second.at("UPLOAD_TARGET");
            log_info("Uploading changes for package: " + name + " to " + real_upload_target);
            dput_source(name, real_upload_target, changes_files, std::vector<std::string>(devel_changes_files.begin(), devel_changes_files.end()));
        }

        fs::remove(fs::path(BASE_DIR)/(name+"_MAIN.orig.tar.gz"));
        log_info("Removed main orig tarball for package: " + name);
    };

    auto prepare_package = [&](const YAML::Node &pkg){
        std::string name = pkg["name"] ? pkg["name"].as<std::string>() : "";
        log_info("Preparing package: " + name);
        if(name.empty()) {
            log_warning("Skipping package due to missing name.");
            return;
        }

        std::string upstream_url = pkg["upstream_url"] ? pkg["upstream_url"].as<std::string>() : ("https://github.com/lxqt/"+name+".git");
        log_info("Upstream URL for " + name + ": " + upstream_url);
        fs::path upstream_destination = fs::path(BASE_DIR)/("upstream-"+name);
        std::optional<std::string> packaging_branch = get_packaging_branch(pkg);
        std::string packaging_url = pkg["packaging_url"] ? pkg["packaging_url"].as<std::string>() : ("https://git.lubuntu.me/Lubuntu/"+name+"-packaging.git");
        log_info("Packaging URL for " + name + ": " + packaging_url);
        fs::path packaging_destination = fs::path(BASE_DIR)/name;

        try {
            log_info("Fetching and checking out upstream repository for " + name);
            git_fetch_and_checkout(upstream_destination, upstream_url, std::nullopt);
        } catch(...) {
            log_error("Failed to prepare upstream repo for " + name);
            return;
        }

        try {
            log_info("Fetching and checking out packaging repository for " + name);
            git_fetch_and_checkout(packaging_destination, packaging_url, packaging_branch);
        } catch(...) {
            log_error("Failed to prepare packaging repo for " + name);
            return;
        }

        try {
            log_info("Updating maintainer scripts for " + name);
            update_maintainer((packaging_destination/"debian").string(), false);
            log_info("Maintainer scripts updated for " + name);
        } catch(std::exception &e) {
            log_warning("update_maintainer: "+std::string(e.what())+" for "+name);
        }

        auto exclusions = get_exclusions(packaging_destination);
        log_info("Creating tarball for " + name);
        create_tarball(name, upstream_destination, exclusions);
        log_info("Tarball created for " + name);

        process_package(pkg);
    };

    std::vector<std::future<void>> futures;
    log_info("Starting package preparation with " + std::to_string(packages.size()) + " packages.");
    for(auto pkg: packages) {
        log_info("Submitting package to be prepared: " + (pkg["name"] ? pkg["name"].as<std::string>() : "Unnamed"));
        futures.push_back(std::async(std::launch::async, prepare_package, pkg));
    }

    for(auto &fut: futures) {
        try {
            fut.get();
            log_info("Package processing completed successfully.");
        } catch(std::exception &e) {
            log_error(std::string("Task generated an exception: ")+e.what());
        }
    }

    if(!skip_cleanup) {
        log_info("Performing cleanup of output directory: " + OUTPUT_DIR);
        fs::remove_all(OUTPUT_DIR);
        log_info("Cleanup completed.");
    } else {
        log_info("Skipping cleanup as per flag.");
    }
    log_info("Publishing Lintian output...");
    publish_lintian();
    log_info("Cleaning old logs.");
    clean_old_logs(fs::path(LOG_DIR));

    log_info("Script completed successfully.");
    return 0;
}
