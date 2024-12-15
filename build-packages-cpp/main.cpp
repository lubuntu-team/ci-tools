#include "common.h"
#include "update_maintainer.h"
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
    std::string full_cmd;
    for (auto &c: cmd) full_cmd += c + " ";
    std::string exec_cmd = full_cmd;
    if(cwd) exec_cmd = "cd " + cwd->string() + " && " + exec_cmd;

    log_info("Executing: " + full_cmd);

    FILE* pipe = popen(exec_cmd.c_str(), "r");
    if(!pipe) {
        log_error("Failed to run: " + full_cmd);
        throw std::runtime_error("Command failed");
    }
    std::stringstream ss;
    {
        char buffer[256];
        while(fgets(buffer,256,pipe)) {
            ss << buffer;
        }
    }
    int ret = pclose(pipe);
    if (ret != 0) {
        log_error("Command failed: " + full_cmd);
        log_error("Output:\n" + ss.str());
        throw std::runtime_error("Command failed");
    }
}

// Initialize libgit2 once
static void git_init_once() {
    static std::once_flag flag;
    std::call_once(flag, [](){
        git_libgit2_init();
    });
}

static void git_fetch_and_checkout(const fs::path &repo_path, const std::string &repo_url, const std::optional<std::string> &branch) {
    git_init_once();
    git_repository* repo = nullptr;
    bool need_clone = false;
    if(fs::exists(repo_path)) {
        int err = git_repository_open(&repo, repo_path.string().c_str());
        if(err<0) {
            log_warning("Cannot open repo at " + repo_path.string() + ", recloning");
            fs::remove_all(repo_path);
            need_clone = true;
        }
    } else {
        need_clone = true;
    }

    if(!need_clone && repo!=nullptr) {
        git_remote* remote = nullptr;
        int err = git_remote_lookup(&remote, repo, "origin");
        if(err<0) {
            log_warning("No origin remote? Recloning");
            git_repository_free(repo);
            fs::remove_all(repo_path);
            need_clone = true;
        } else {
            const char* url = git_remote_url(remote);
            if(!url || repo_url!=url) {
                log_info("Remote URL differs. Removing and recloning.");
                git_remote_free(remote);
                git_repository_free(repo);
                fs::remove_all(repo_path);
                need_clone = true;
            } else {
                // fetch
                git_remote_free(remote);
                git_remote* origin = nullptr;
                git_remote_lookup(&origin, repo, "origin");
                git_fetch_options fetch_opts = GIT_FETCH_OPTIONS_INIT;
                git_remote_fetch(origin, nullptr, &fetch_opts, nullptr);
                git_remote_free(origin);

                if(branch) {
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
        git_clone_options clone_opts = GIT_CLONE_OPTIONS_INIT;
        git_checkout_options co_opts = GIT_CHECKOUT_OPTIONS_INIT;
        co_opts.checkout_strategy = GIT_CHECKOUT_FORCE;
        clone_opts.checkout_opts = co_opts;
        git_repository* newrepo = nullptr;
        int err = git_clone(&newrepo, repo_url.c_str(), repo_path.string().c_str(), &clone_opts);
        if(err<0) {
            const git_error* e = git_error_last();
            log_error(std::string("Git clone failed: ")+(e?e->message:"unknown"));
            throw std::runtime_error("Git clone failed");
        }
        if(branch) {
            git_reference* ref = nullptr;
            std::string fullbranch = "refs/remotes/origin/" + *branch;
            if(git_reference_lookup(&ref, newrepo, fullbranch.c_str())==0) {
                git_object* target = nullptr;
                git_reference_peel(&target, ref, GIT_OBJECT_COMMIT);
                git_checkout_options co_opts = GIT_CHECKOUT_OPTIONS_INIT;
                co_opts.checkout_strategy = GIT_CHECKOUT_FORCE;
                git_checkout_tree(newrepo, target, &co_opts);
                git_reference_free(ref);
                git_repository_set_head_detached(newrepo, git_object_id(target));
                git_object_free(target);
            } else {
                log_error("Git checkout of branch " + *branch + " failed after clone.");
                git_repository_free(newrepo);
                throw std::runtime_error("Branch checkout failed");
            }
        }
        git_repository_free(newrepo);
    }
}

static YAML::Node load_config(const fs::path &config_path) {
    YAML::Node config = YAML::LoadFile(config_path.string());
    if (!config["packages"] || !config["releases"]) {
        throw std::runtime_error("Config file must contain 'packages' and 'releases' sections.");
    }
    return config;
}

static void publish_lintian() {
    if(!BASE_LINTIAN_DIR.empty() && fs::exists(BASE_LINTIAN_DIR)) {
        for (auto &p : fs::recursive_directory_iterator(BASE_LINTIAN_DIR)) {
            if (fs::is_regular_file(p)) {
                fs::path rel = fs::relative(p.path(), BASE_LINTIAN_DIR);
                fs::path dest = fs::path(REAL_LINTIAN_DIR) / rel;
                fs::create_directories(dest.parent_path());
                std::error_code ec;
                fs::copy_file(p.path(), dest, fs::copy_options::overwrite_existing, ec);
            }
        }
        fs::remove_all(BASE_LINTIAN_DIR);
    }
}

// Define get_exclusions here before usage
static std::vector<std::string> get_exclusions(const fs::path &packaging) {
    std::vector<std::string> exclusions;
    fs::path cpr = packaging / "debian" / "copyright";
    if(!fs::exists(cpr)) return exclusions;

    std::ifstream f(cpr);
    if(!f) return exclusions;
    std::string line;
    bool found = false;
    while(std::getline(f,line)) {
        if (line.find("Files-Excluded:") != std::string::npos) {
            size_t pos=line.find(':');
            if(pos!=std::string::npos) {
                std::string excl = line.substr(pos+1);
                std::istringstream iss(excl);
                std::string token;
                while(iss>>token) {
                    exclusions.push_back(token);
                }
            }
            break;
        }
    }
    return exclusions;
}

int main(int argc, char** argv) {
    fs::create_directories(LOG_DIR);
    fs::create_directories(OUTPUT_DIR);

    auto now = std::time(nullptr);
    std::tm tm = *std::gmtime(&now);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y%m%dT%H%M%S", &tm);
    std::string current_time = buf;

    std::string uuid_part = current_time.substr(0,8);
    BASE_LINTIAN_DIR = BASE_OUTPUT_DIR + "/.lintian.tmp." + uuid_part;
    fs::create_directories(BASE_LINTIAN_DIR);

    fs::path log_file = fs::path(LOG_DIR) / (current_time + ".log");
    log_file_stream.open(log_file);
    if(!log_file_stream.is_open()) {
        std::cerr<<"[ERROR] Unable to open log file.\n";
        return 1;
    }

    bool skip_dput = false;
    bool skip_cleanup = false;
    std::string config_path;
    for(int i=1; i<argc; i++) {
        std::string arg=argv[i];
        if(arg=="--skip-dput") {
            skip_dput=true;
        } else if(arg=="--skip-cleanup") {
            skip_cleanup=true;
        } else if(arg.rfind("--urgency-level=",0)==0) {
            urgency_level_override = arg.substr(std::string("--urgency-level=").size());
        } else if(arg.rfind("--workers=",0)==0) {
            worker_count = std::stoi(arg.substr(std::string("--workers=").size()));
            if(worker_count<1) worker_count=1;
        } else if(config_path.empty()) {
            config_path = arg;
        }
    }

    if(config_path.empty()) {
        log_error("No config file specified.");
        return 1;
    }

    setenv("DEBFULLNAME", DEBFULLNAME.c_str(),1);
    setenv("DEBEMAIL", DEBEMAIL.c_str(),1);

    YAML::Node config;
    try {
        config = load_config(config_path);
    } catch (std::exception &e) {
        log_error(std::string("Error loading config file: ")+e.what());
        return 1;
    }

    auto packages = config["packages"];
    auto releases = config["releases"];

    fs::current_path(BASE_DIR);

    auto get_packaging_branch = [&](const YAML::Node &pkg)->std::optional<std::string>{
        if(pkg["packaging_branch"] && pkg["packaging_branch"].IsScalar()) {
            return pkg["packaging_branch"].as<std::string>();
        } else if (releases.size()>0) {
            return "ubuntu/" + releases[0].as<std::string>();
        }
        return std::nullopt;
    };

    auto parse_version = [&](const fs::path &changelog_path){
        std::ifstream f(changelog_path);
        if(!f) throw std::runtime_error("Changelog not found: " + changelog_path.string());
        std::string first_line;
        std::getline(f, first_line);
        size_t start = first_line.find('(');
        size_t end = first_line.find(')');
        if(start==std::string::npos||end==std::string::npos) throw std::runtime_error("Invalid changelog format");
        std::string version_match = first_line.substr(start+1,end-(start+1));
        std::string epoch;
        std::string upstream_version = version_match;
        if(auto pos=version_match.find(':'); pos!=std::string::npos) {
            epoch = version_match.substr(0,pos);
            upstream_version = version_match.substr(pos+1);
        }
        if(auto pos=upstream_version.find('-'); pos!=std::string::npos) {
            upstream_version=upstream_version.substr(0,pos);
        }
        std::regex git_regex("(\\+git[0-9]+)?(~[a-z]+)?$");
        upstream_version = std::regex_replace(upstream_version, git_regex, "");
        auto t = std::time(nullptr);
        std::tm tm = *std::gmtime(&t);
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y%m%d%H%M", &tm);
        std::string current_date = buf;
        std::string version;
        if(!epoch.empty()) {
            version = epoch + ":" + upstream_version + "+git" + current_date;
        } else {
            version = upstream_version + "+git" + current_date;
        }
        return version;
    };

    auto run_source_lintian = [&](const std::string &name, const fs::path &source_path){
        log_info("Running Lintian for " + name);
        fs::path temp_file = fs::temp_directory_path() / ("lintian_suppress_" + name + ".txt");
        {
            std::ofstream of(temp_file);
            for (auto &tag: SUPPRESSED_LINTIAN_TAGS) {
                of<<tag<<"\n";
            }
        }
        std::string cmd = "lintian -EvIL +pedantic --suppress-tags-from-file " + temp_file.string() + " " + source_path.string() + " 2>&1";
        FILE* pipe = popen(cmd.c_str(),"r");
        std::stringstream ss;
        if(pipe) {
            char buffer[256];
            while(fgets(buffer,256,pipe)) {
                ss<<buffer;
            }
            int ret = pclose(pipe);
            fs::remove(temp_file);
            if(ret!=0) {
                log_error("Lintian failed:\n"+ss.str());
                if(!ss.str().empty()) {
                    fs::path pkgdir = fs::path(BASE_LINTIAN_DIR)/name;
                    fs::create_directories(pkgdir);
                    std::ofstream out(pkgdir/"source.txt",std::ios::app);
                    out<<ss.str()<<"\n";
                }
            } else {
                if(!ss.str().empty()) {
                    fs::path pkgdir = fs::path(BASE_LINTIAN_DIR)/name;
                    fs::create_directories(pkgdir);
                    std::ofstream out(pkgdir/"source.txt",std::ios::app);
                    out<<ss.str()<<"\n";
                }
            }
        } else {
            fs::remove(temp_file);
            log_error("Failed to run lintian");
        }
        log_info("Lintian run for " + name + " is complete");
    };

    auto dput_source = [&](const std::string &name, const std::string &upload_target, const std::vector<std::string> &changes_files, const std::vector<std::string> &devel_changes_files){
        if(!changes_files.empty()) {
            std::string hr_changes;
            for(auto &c: changes_files) hr_changes += c+" ";
            log_info("Uploading "+hr_changes+"to "+upload_target+" using dput");
            std::vector<std::string> cmd = {"dput",upload_target};
            for(auto &c: changes_files) cmd.push_back(c);
            try {
                run_command_silent_on_success(cmd, OUTPUT_DIR);
                log_info("Completed upload of changes to "+upload_target);
                for(auto &file: devel_changes_files) {
                    if(!file.empty()) {
                        run_source_lintian(name, file);
                    }
                }
            } catch (...) {
                // error logged already
            }
        }
    };

    auto update_changelog = [&](const fs::path &packaging_dir, const std::string &release, const std::string &version_with_epoch){
        std::string name = packaging_dir.filename().string();
        log_info("Updating changelog for " + name + " to version " + version_with_epoch + "-0ubuntu1~ppa1");
        run_command_silent_on_success({"git","checkout","debian/changelog"}, packaging_dir);
        std::vector<std::string> cmd={
            "dch","--distribution",release,"--package",name,"--newversion",version_with_epoch+"-0ubuntu1~ppa1","--urgency",urgency_level_override,"CI upload."
        };
        run_command_silent_on_success(cmd, packaging_dir);
    };

    auto build_package = [&](const fs::path &packaging_dir, const std::map<std::string,std::string> &env_vars, bool large) {
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
        }

        std::error_code ec;
        fs::path temp_packaging_dir = temp_dir/name;
        fs::create_directories(temp_packaging_dir,ec);
        fs::copy(packaging_dir/"debian", temp_packaging_dir/"debian", fs::copy_options::recursive, ec);

        std::string tarball_name = name+"_"+env_vars.at("VERSION")+".orig.tar.gz";
        fs::path tarball_source = fs::path(BASE_DIR)/(name+"_MAIN.orig.tar.gz");
        fs::path tarball_dest = temp_dir/tarball_name;
        fs::copy_file(tarball_source,tarball_dest,fs::copy_options::overwrite_existing,ec);

        for (auto &e: env_vars) {
            setenv(e.first.c_str(), e.second.c_str(),1);
        }

        std::vector<std::string> cmd_build={"debuild","--no-lintian","-S","-d","-sa","-nc"};
        try {
            run_command_silent_on_success(cmd_build,temp_packaging_dir);
            run_command_silent_on_success({"git","checkout","debian/changelog"}, packaging_dir);
        } catch(...) {
            fs::remove_all(temp_dir,ec);
            throw;
        }

        std::string pattern = name+"_"+env_vars.at("VERSION");
        for(auto &entry: fs::directory_iterator(temp_dir)) {
            std::string fname=entry.path().filename().string();
            if(fname.rfind(pattern,0)==0) {
                fs::path dest=fs::path(OUTPUT_DIR)/fname;
                fs::copy_file(entry.path(),dest,fs::copy_options::overwrite_existing,ec);
                log_info("Copied "+fname+" to "+OUTPUT_DIR);
            }
        }

        std::string changes_file;
        for(auto &entry : fs::directory_iterator(OUTPUT_DIR)) {
            std::string fname=entry.path().filename().string();
            if(fname.rfind(name+"_"+env_vars.at("VERSION"),0)==0 && fname.ends_with("_source.changes")) {
                changes_file=entry.path().string();
            }
        }

        fs::remove_all(temp_dir,ec);

        if(changes_file.empty()) {
            log_error("No changes file found after build.");
            throw std::runtime_error("Changes file not found");
        }
        log_info("Built package, changes file: "+changes_file);
        return changes_file;
    };

    auto process_package = [&](const YAML::Node &pkg){
        std::string name = pkg["name"] ? pkg["name"].as<std::string>() : "";
        std::string upload_target = pkg["upload_target"] ? pkg["upload_target"].as<std::string>() : "ppa:lubuntu-ci/unstable-ci-proposed";
        if(name.empty()) {
            log_warning("Skipping package due to missing name.");
            return;
        }
        fs::path packaging_destination = fs::path(BASE_DIR)/name;
        fs::path changelog_path = packaging_destination/"debian"/"changelog";
        std::string version = parse_version(changelog_path);

        bool large = pkg["large"] ? pkg["large"].as<bool>() : false;
        std::vector<std::pair<std::string,std::map<std::string,std::string>>> built_changes;

        std::string epoch;
        std::string version_no_epoch=version;
        if(auto pos=version.find(':');pos!=std::string::npos) {
            epoch=version.substr(0,pos);
            version_no_epoch=version.substr(pos+1);
        }

        for (auto rel : releases) {
            std::string release = rel.as<std::string>();
            log_info("Building "+name+" for "+release);

            std::string release_version_no_epoch = version_no_epoch + "~" + release;
            fs::path tarball_source = fs::path(BASE_DIR)/(name+"_MAIN.orig.tar.gz");
            fs::path tarball_dest = fs::path(BASE_DIR)/(name+"_"+release_version_no_epoch+".orig.tar.gz");
            fs::copy_file(tarball_source,tarball_dest,fs::copy_options::overwrite_existing);

            std::string version_for_dch = epoch.empty()? release_version_no_epoch : (epoch+":"+release_version_no_epoch);

            std::map<std::string,std::string> env_map;
            env_map["DEBFULLNAME"]=DEBFULLNAME;
            env_map["DEBEMAIL"]=DEBEMAIL;
            env_map["VERSION"]=release_version_no_epoch;
            env_map["UPLOAD_TARGET"]=upload_target;

            try {
                update_changelog(packaging_destination, release, version_for_dch);
                std::string changes_file = build_package(packaging_destination, env_map, large);
                if(!changes_file.empty()) {
                    built_changes.push_back({changes_file,env_map});
                }
            } catch(std::exception &e) {
                log_error("Error processing package '"+name+"' for release '"+release+"': "+std::string(e.what()));
            }

            fs::remove(tarball_dest);
        }

        std::vector<std::string> changes_files;
        for(auto &bc: built_changes) {
            fs::path cf(bc.first);
            changes_files.push_back(cf.filename().string());
        }

        std::unordered_set<std::string> devel_changes_files;
        if(releases.size()>0) {
            std::string first_release = releases[0].as<std::string>();
            for (auto &f: changes_files) {
                if(f.find("~"+first_release)!=std::string::npos) {
                    devel_changes_files.insert((fs::path(OUTPUT_DIR)/f).string());
                } else {
                    devel_changes_files.insert(std::string());
                }
            }
        }

        if(built_changes.empty()) return;

        if(getenv("DEBFULLNAME")==nullptr) setenv("DEBFULLNAME",DEBFULLNAME.c_str(),1);
        if(getenv("DEBEMAIL")==nullptr) setenv("DEBEMAIL",DEBEMAIL.c_str(),1);

        if(skip_dput) {
            for (auto &file : devel_changes_files) {
                if(!file.empty()) {
                    run_source_lintian(name,file);
                }
            }
        } else {
            std::string real_upload_target = built_changes[0].second.at("UPLOAD_TARGET");
            dput_source(name, real_upload_target, changes_files, std::vector<std::string>(devel_changes_files.begin(), devel_changes_files.end()));
        }

        fs::remove(fs::path(BASE_DIR)/(name+"_MAIN.orig.tar.gz"));
    };

    auto prepare_package = [&](const YAML::Node &pkg){
        std::string name = pkg["name"] ? pkg["name"].as<std::string>() : "";
        if(name.empty()) {
            log_warning("Skipping package due to missing name.");
            return;
        }

        std::string upstream_url = pkg["upstream_url"] ? pkg["upstream_url"].as<std::string>() : ("https://github.com/lxqt/"+name+".git");
        fs::path upstream_destination = fs::path(BASE_DIR)/("upstream-"+name);
        std::optional<std::string> packaging_branch = get_packaging_branch(pkg);
        std::string packaging_url = pkg["packaging_url"] ? pkg["packaging_url"].as<std::string>() : ("https://git.lubuntu.me/Lubuntu/"+name+"-packaging.git");
        fs::path packaging_destination = fs::path(BASE_DIR)/name;

        try {
            git_fetch_and_checkout(upstream_destination, upstream_url, std::nullopt);
        } catch(...) {
            log_error("Failed to prepare upstream repo for "+name);
            return;
        }

        try {
            git_fetch_and_checkout(packaging_destination, packaging_url, packaging_branch);
        } catch(...) {
            log_error("Failed to prepare packaging repo for "+name);
            return;
        }

        try {
            update_maintainer((packaging_destination/"debian").string(), false);
        } catch(std::exception &e) {
            log_warning("update_maintainer: "+std::string(e.what())+" for "+name);
        }

        auto exclusions = get_exclusions(packaging_destination);
        create_tarball(name, upstream_destination, exclusions);

        process_package(pkg);
    };

    std::vector<std::future<void>> futures;
    for(auto pkg: packages) {
        futures.push_back(std::async(std::launch::async, prepare_package, pkg));
    }

    for(auto &fut: futures) {
        try {
            fut.get();
        } catch(std::exception &e) {
            log_error(std::string("Task generated an exception: ")+e.what());
        }
    }

    if(!skip_cleanup) {
        fs::remove_all(OUTPUT_DIR);
    }
    log_info("Publishing Lintian output...");
    publish_lintian();
    clean_old_logs(fs::path(LOG_DIR));

    log_info("Script completed successfully.");
    return 0;
}
