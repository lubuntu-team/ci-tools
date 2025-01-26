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

#include "task_queue.h"
#include "ci_logic.h"
#include "lubuntuci_lib.h"
#include "common.h"
#include "utilities.h"
#include "db_common.h"

#include <yaml-cpp/yaml.h>
#include <filesystem>
#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <regex>
#include <chrono>
#include <ctime>
#include <fstream>
#include <git2.h>
#include <mutex>
#include <ranges>

#include <QSqlQuery>
#include <QSqlError>
#include <QThread>

namespace fs = std::filesystem;

static std::mutex g_cfg_mutex;
static std::atomic<unsigned int> thread_id_counter{1};

/**
 * Merge "packages" and "releases" from partial into master.
 */
static void merge_yaml_nodes(YAML::Node &master, const YAML::Node &partial) {
    // Merge packages:
    if (partial["packages"]) {
        if (!master["packages"]) {
            master["packages"] = YAML::Node(YAML::NodeType::Sequence);
        }
        for (auto pkg : partial["packages"]) {
            master["packages"].push_back(pkg);
        }
    }
    // Merge releases:
    if (partial["releases"]) {
        if (!master["releases"]) {
            master["releases"] = YAML::Node(YAML::NodeType::Sequence);
        }
        for (auto rel : partial["releases"]) {
            master["releases"].push_back(rel);
        }
    }
}

// This returns the following information about a commit:
//  1) commit_hash
//  2) commit_summary
//  3) commit_message
//  4) commit_datetime
//  5) commit_author
//  6) commit_committer
GitCommit get_commit_from_pkg_repo(const std::string& repo_name, std::shared_ptr<Log> log) {
    // Ensure libgit2 is initialized
    ensure_git_inited();

    // Define the repository path
    std::filesystem::path repo_dir = repo_name;

    git_repository* repo = nullptr;
    git_revwalk* walker = nullptr;
    git_commit* commit = nullptr;

    static const std::vector<std::string> COMMIT_SUMMARY_EXCLUSIONS = {
        "GIT_SILENT",
        "SVN_SILENT",
        "Qt Submodule Update Bot",
        "CMake Nightly Date Stamp",
        "https://translate.lxqt-project.org/"
    };

    GitCommit _tmp_commit;
    std::string commit_hash;
    std::string commit_summary;
    std::string commit_message;
    std::chrono::zoned_time<std::chrono::seconds> commit_datetime{
        std::chrono::locate_zone("UTC"),
        std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::time_point{})
    };
    std::string commit_author;
    std::string commit_committer;

    // Attempt to open the repository
    int error = git_repository_open(&repo, repo_dir.c_str());
    if (error != 0) {
        const git_error* e = git_error_last();
        std::string msg = (e && e->message) ? e->message : "unknown error";
        log->append("Failed to open repository: " + msg);
        return GitCommit();
    }

    // Initialize the revwalk
    error = git_revwalk_new(&walker, repo);
    if (error != 0) {
        const git_error* e = git_error_last();
        log->append("Failed to create revwalk: " + std::string(e && e->message ? e->message : "unknown error"));
        git_repository_free(repo);
        return GitCommit();
    }

    // Push HEAD to the walker
    error = git_revwalk_push_head(walker);
    if (error != 0) {
        const git_error* e = git_error_last();
        log->append("Failed to push HEAD to revwalk: " + std::string(e && e->message ? e->message : "unknown error"));
        git_revwalk_free(walker);
        git_repository_free(repo);
        return GitCommit();
    }

    // Optional: Sort commits in topological order and by time
    git_revwalk_sorting(walker, GIT_SORT_TIME | GIT_SORT_TOPOLOGICAL);

    bool found_valid_commit = false;

    // Iterate through commits
    git_oid oid;
    while ((error = git_revwalk_next(&oid, walker)) == 0) {
        // Lookup the commit object using the oid
        error = git_commit_lookup(&commit, repo, &oid);
        if (error != 0) {
            const git_error* e = git_error_last();
            log->append("Failed to lookup commit: " + std::string(e && e->message ? e->message : "unknown error"));
            continue; // Skip to next commit
        }

        // Extract commit summary
        const char* summary_cstr = git_commit_summary(commit);
        if (!summary_cstr) {
            git_commit_free(commit);
            continue; // No summary, skip
        }
        std::string current_summary = summary_cstr;

        // Check if the commit summary contains any exclusion strings
        bool is_excluded = false;
        for (const auto& excl : COMMIT_SUMMARY_EXCLUSIONS) {
            if (current_summary.find(excl) != std::string::npos) {
                is_excluded = true;
                char hash_str[GIT_OID_HEXSZ + 1];
                git_oid_tostr(hash_str, sizeof(hash_str), &oid);
                log->append("Skipping commit " + std::string(hash_str) +
                            " due to exclusion string: \"" + excl + "\"");
                break;
            }
        }

        if (is_excluded) {
            git_commit_free(commit);
            continue; // Skip this commit and move to the next one
        }

        // 1) Extract commit hash
        char hash_str[GIT_OID_HEXSZ + 1];
        git_oid_tostr(hash_str, sizeof(hash_str), &oid);
        commit_hash = hash_str;

        // 2) Extract commit message
        const char* message = git_commit_message(commit);
        if (message) {
            commit_message = message;
        }

        // 3) Extract commit datetime and convert to UTC
        git_time_t c_time = git_commit_time(commit);
        int c_time_offset = git_commit_time_offset(commit); // Offset in minutes from UTC
        std::chrono::system_clock::time_point commit_tp =
            std::chrono::system_clock::from_time_t(static_cast<std::time_t>(c_time));
        std::chrono::minutes offset_minutes(c_time_offset);
        auto utc_time_tp = commit_tp - std::chrono::duration_cast<std::chrono::system_clock::duration>(offset_minutes);
        commit_datetime = std::chrono::zoned_time<std::chrono::seconds>{
            std::chrono::locate_zone("UTC"),
            std::chrono::floor<std::chrono::seconds>(utc_time_tp)
        };

        // 4) Extract commit author
        git_signature* author = nullptr;
        error = git_commit_author_with_mailmap(&author, commit, nullptr);
        if (error == 0 && author) {
            commit_author = std::format("{} <{}>", author->name, author->email);
            git_signature_free(author);
        }

        // 5) Extract commit committer
        git_signature* committer_sig = nullptr;
        error = git_commit_committer_with_mailmap(&committer_sig, commit, nullptr);
        if (error == 0 && committer_sig) {
            commit_committer = std::format("{} <{}>", committer_sig->name, committer_sig->email);
            git_signature_free(committer_sig);
        }

        // Cleanup the commit object
        git_commit_free(commit);
        commit = nullptr;

        // Construct and return the GitCommit object with collected data
        GitCommit git_commit_instance(
            commit_hash,
            current_summary, // Use the current commit summary
            commit_message,
            commit_datetime,
            commit_author,
            commit_committer
        );

        // Check if the commit already exists in the DB
        auto existing_commit = _tmp_commit.get_commit_by_hash(commit_hash);
        if (existing_commit) {
            found_valid_commit = true;
            // Cleanup revwalk and repository before returning
            git_revwalk_free(walker);
            git_repository_free(repo);
            return *existing_commit;
        } else {
            // Insert the new commit into the DB
            found_valid_commit = true;
            // Cleanup revwalk and repository before returning
            git_revwalk_free(walker);
            git_repository_free(repo);
            return git_commit_instance;
        }
    }

    if (error != GIT_ITEROVER && error != 0) {
        const git_error* e = git_error_last();
        log->append("Error during revwalk: " + std::string(e && e->message ? e->message : "unknown error"));
    }

    // Cleanup
    git_revwalk_free(walker);
    git_repository_free(repo);

    if (!found_valid_commit) {
        log->append("No valid commit found without exclusions in repository: " + repo_name);
        return GitCommit();
    }

    // This point should not be reached if a valid commit is found
    return GitCommit();
}

/**
 * Load a YAML file from a given path.
 */
YAML::Node CiLogic::load_yaml_config(const fs::path &config_path) {
    if (!fs::exists(config_path)) {
        throw std::runtime_error("Config file does not exist: " + config_path.string());
    }
    return YAML::LoadFile(config_path.string());
}

/**
 * init_global():
 *   1. Reads all *.yaml in /srv/lubuntu-ci/repos/ci-tools/configs/
 *   2. Merges them into g_config.
 *   3. Ensures libgit2 is initialized once.
 */
void CiLogic::init_global() {
    std::lock_guard<std::mutex> lk(g_cfg_mutex);
    Branch _tmp_brnch;
    Package _tmp_pkg;
    PackageConf _tmp_pkg_conf;
    Release _tmp_rel;

    ensure_git_inited();
    if (!init_database("/srv/lubuntu-ci/repos/ci-tools/lubuntu_ci.db")) return;

    if (branches.empty() || packages.empty() || releases.empty() || packageconfs.empty()) {
        YAML::Node g_config;
        fs::path config_dir = "/srv/lubuntu-ci/repos/ci-tools/configs";
        if (!fs::exists(config_dir) || !fs::is_directory(config_dir)) {
            std::cerr << "[WARNING] Config directory not found: " << config_dir << "\n";
            std::cerr << "[WARNING] Continuing with empty config.\n";
            return;
        }

        YAML::Node merged;
        bool found_any_yaml = false;

        for (auto &entry : fs::directory_iterator(config_dir)) {
            if (entry.is_regular_file()) {
                auto p = entry.path();
                if (p.extension() == ".yaml") {
                    found_any_yaml = true;
                    try {
                        YAML::Node partial = YAML::LoadFile(p.string());
                        merge_yaml_nodes(merged, partial);
                    } catch (std::exception &ex) {
                        std::cerr << "[WARNING] Could not parse YAML in " << p.string()
                                  << ": " << ex.what() << "\n";
                    }
                }
            }
        }

        if (!found_any_yaml) {
            std::cerr << "[WARNING] No .yaml files found in " << config_dir << "\n";
            std::cerr << "[WARNING] Continuing with empty config.\n";
        }

        g_config = merged;

        if (g_config["packages"]) {
            log_info("Merged config has "
                     + std::to_string(g_config["packages"].size())
                     + " 'packages' items total.");
        } else {
            log_error("No 'packages' found in the final merged YAML config!");
        }
        if (g_config["releases"]) {
            log_info("Merged config has "
                     + std::to_string(g_config["releases"].size())
                     + " 'releases' items total.");
        }

        // Set the packages in the DB
        YAML::Node yaml_packages = g_config["packages"];
        if (!_tmp_pkg.set_packages(yaml_packages)) {
            log_error("Failed to set packages.");
        }
        packages = _tmp_pkg.get_packages();

        // Set the releases in the DB
        YAML::Node yaml_releases = g_config["releases"];
        if (!_tmp_rel.set_releases(yaml_releases)) {
            log_error("Failed to set releases.");
        }
        releases = _tmp_rel.get_releases();

        // Add missing packageconf entries
        if (!_tmp_pkg_conf.set_package_confs()) {
            log_error("Failed to set package configurations.");
        }
        set_packageconfs(_tmp_pkg_conf.get_package_confs(get_job_statuses()));

        // Finally, store the branches
        if (branches.empty()) {
            branches = _tmp_brnch.get_branches();
        }
    }
}

/**
 * Convert a YAML node to CiProject
 */
CiProject CiLogic::yaml_to_project(const YAML::Node &pkg_node) {
    CiProject project;
    project.name = pkg_node["name"].as<std::string>();
    project.upload_target = pkg_node["upload_target"]
        ? pkg_node["upload_target"].as<std::string>()
        : "ppa:lubuntu-ci/unstable-ci-proposed";
    project.upstream_url  = pkg_node["upstream_url"]
        ? pkg_node["upstream_url"].as<std::string>()
        : ("https://github.com/lxqt/" + project.name + ".git");
    project.packaging_url = pkg_node["packaging_url"]
        ? pkg_node["packaging_url"].as<std::string>()
        : ("https://git.lubuntu.me/Lubuntu/" + project.name + "-packaging.git");
    project.packaging_branch =
        pkg_node["packaging_branch"]
            ? std::optional<std::string>(pkg_node["packaging_branch"].as<std::string>())
            : std::nullopt;
    project.large = pkg_node["large"] ? pkg_node["large"].as<bool>() : false;
    return project;
}

// Trampoline function to bridge C callback to C++ lambda
static int submodule_trampoline(git_submodule* sm, const char* name, void* payload) {
    // Cast payload back to the C++ lambda
    auto* callback = static_cast<std::function<int(git_submodule*, const char*, void*)>*>(payload);
    return (*callback)(sm, name, payload);
}

static int progress_cb(const git_indexer_progress *stats, void *payload) {
    if (stats->total_objects == 0) return 0;

    // Calculate percentage
    int pct = static_cast<int>((static_cast<double>(stats->received_objects) / stats->total_objects) * 100);
    if (pct % 5 == 0) {
        // 0 <= pct <= 100
        if (pct > 100) pct = 100;
        if (pct < 1) pct = 1;
        std::string progress_str = (pct < 10 ? "0" : "") + std::to_string(pct) + "%";

        auto log = static_cast<std::shared_ptr<Log>*>(payload);
        (*log)->append(progress_str);
    }

    return 0;
}

/**
 * clone_or_fetch: clone if needed, else fetch
 */
void CiLogic::clone_or_fetch(const std::filesystem::path &repo_dir,
                             const std::string &repo_url,
                             const std::optional<std::string> &branch,
                             std::shared_ptr<Log> log)
{
    ensure_git_inited();

    git_repository* repo = nullptr;
    int error = git_repository_open(&repo, repo_dir.c_str());
    if (error == GIT_ENOTFOUND) {
        log->append("Cloning: " + repo_url + " => " + repo_dir.string());
        git_clone_options opts = GIT_CLONE_OPTIONS_INIT;
        if (branch.has_value()) {
            opts.checkout_branch = branch->c_str();
        }

        git_remote_callbacks callbacks = GIT_REMOTE_CALLBACKS_INIT;
        callbacks.transfer_progress = progress_cb;
        callbacks.payload = &log;
        git_fetch_options fetch_opts = GIT_FETCH_OPTIONS_INIT;
        fetch_opts.callbacks = callbacks;
        opts.fetch_opts = fetch_opts;

        opts.checkout_opts.checkout_strategy |= GIT_CHECKOUT_UPDATE_SUBMODULES;

        error = git_clone(&repo, repo_url.c_str(), repo_dir.c_str(), &opts);
        if (error != 0) {
            const git_error *e = git_error_last();
            throw std::runtime_error("Failed to clone: " +
                                     std::string(e && e->message ? e->message : "unknown"));
        }
        log->append("Repo cloned OK.");
    }
    else if (error == 0) {
        git_remote *remote = nullptr;
        if (git_remote_lookup(&remote, repo, "origin") != 0) {
            const git_error *e = git_error_last();
            git_repository_free(repo);
            throw std::runtime_error("No remote origin: " +
                                     std::string(e && e->message ? e->message : "unknown"));
        }

        git_remote_callbacks callbacks = GIT_REMOTE_CALLBACKS_INIT;
        callbacks.transfer_progress = progress_cb;
        callbacks.payload = &log;
        git_fetch_options fetch_opts = GIT_FETCH_OPTIONS_INIT;
        fetch_opts.callbacks = callbacks;

        if (git_remote_fetch(remote, nullptr, &fetch_opts, nullptr) < 0) {
            const git_error *e = git_error_last();
            git_remote_free(remote);
            git_repository_free(repo);
            throw std::runtime_error("Fetch failed: " +
                                     std::string(e && e->message ? e->message : "unknown"));
        }

        std::string detected_branch = "master";
        git_reference* head_ref = nullptr;
        error = git_reference_lookup(&head_ref, repo, "refs/remotes/origin/HEAD");
        if (error == 0 && head_ref != nullptr) {
            if (git_reference_type(head_ref) & GIT_REFERENCE_SYMBOLIC) {
                const char* symref = git_reference_symbolic_target(head_ref);
                if (symref) {
                    std::string s = symref;
                    std::string prefix = "refs/remotes/origin/";
                    if (s.find(prefix) == 0) {
                        detected_branch = s.substr(prefix.size());
                    }
                }
            }
            git_reference_free(head_ref);
        }

        std::string b = branch.value_or(detected_branch);
        log->append("Using branch: " + b);

        bool successPull = false;
        do {
            std::string localRef  = "refs/heads/" + b;
            std::string remoteRef = "refs/remotes/origin/" + b;

            git_reference* localBranch = nullptr;
            if (git_reference_lookup(&localBranch, repo, localRef.c_str()) == GIT_ENOTFOUND) {
                git_object* remObj = nullptr;
                if (git_revparse_single(&remObj, repo, remoteRef.c_str()) == 0) {
                    git_reference* newB = nullptr;
                    git_branch_create(&newB, repo, b.c_str(), (const git_commit*)remObj, 0);
                    if (newB) git_reference_free(newB);
                    git_object_free(remObj);
                    git_reference_lookup(&localBranch, repo, localRef.c_str());
                }
            }
            if (!localBranch) break;

            git_object* remoteObj = nullptr;
            if (git_revparse_single(&remoteObj, repo, remoteRef.c_str()) < 0) {
                git_reference_free(localBranch);
                break;
            }
            git_oid remoteOid = *git_object_id(remoteObj);

            git_reference* updated = nullptr;
            int ffErr = git_reference_set_target(&updated, localBranch, &remoteOid, "Fast-forward");
            git_reference_free(localBranch);
            git_object_free(remoteObj);
            if (ffErr < 0) {
                if (updated) git_reference_free(updated);
                break;
            }
            {
                git_object* obj = nullptr;
                if (git_revparse_single(&obj, repo, localRef.c_str()) == 0) {
                    git_checkout_options co = GIT_CHECKOUT_OPTIONS_INIT;
                    // Use a more forceful checkout strategy
                    co.checkout_strategy = GIT_CHECKOUT_FORCE | GIT_CHECKOUT_UPDATE_SUBMODULES;
                    if (git_checkout_tree(repo, obj, &co) == 0) {
                        if (git_repository_set_head(repo, localRef.c_str()) == 0) {
                            // Perform a hard reset to ensure working directory and index match HEAD
                            error = git_reset(repo, obj, GIT_RESET_HARD, nullptr);
                            if (error != 0) {
                                const git_error* e = git_error_last();
                                log->append("Failed to reset repository: " + std::string(e && e->message ? e->message : "unknown error"));
                                git_repository_free(repo);
                                throw std::runtime_error("Failed to reset repository after checkout.");
                            }
                            successPull = true;
                        }
                    }
                    git_object_free(obj);
                }
            }
            if (updated) git_reference_free(updated);
        } while(false);

        if (!successPull) {
            std::string bRem = "refs/remotes/origin/" + b;
            git_object* origObj = nullptr;
            if (git_revparse_single(&origObj, repo, bRem.c_str()) == 0) {
                git_reset(repo, origObj, GIT_RESET_HARD, nullptr);
                git_object_free(origObj);

                git_oid newOid;
                if (git_revparse_single(&origObj, repo, bRem.c_str()) == 0) {
                    newOid = *git_object_id(origObj);
                    git_object_free(origObj);
                    std::string lRef = "refs/heads/" + b;
                    git_reference* fRef = nullptr;
                    git_reference_create(&fRef, repo, lRef.c_str(), &newOid, 1,
                                         "Forced local update");
                    if (fRef) git_reference_free(fRef);
                    git_object* co = nullptr;
                    if (git_revparse_single(&co, repo, lRef.c_str()) == 0) {
                        git_checkout_options o = GIT_CHECKOUT_OPTIONS_INIT;
                        o.checkout_strategy = GIT_CHECKOUT_FORCE;
                        if (!git_checkout_tree(repo, co, &o))
                            git_repository_set_head(repo, lRef.c_str());
                        git_object_free(co);
                    }
                }
            }
        }

        std::function<int(git_submodule*, const char*, void*)> submodule_callback;
        submodule_callback = [&](git_submodule* sm, const char* name, void* payload) -> int {
            // Initialize submodule
            if (git_submodule_init(sm, 1) != 0) {
                log->append("Failed to initialize submodule " + std::string(name) + "\n");
                return 0; // Continue with other submodules
            }

            // Set up update options
            git_submodule_update_options opts = GIT_SUBMODULE_UPDATE_OPTIONS_INIT;
            git_remote_callbacks callbacks = GIT_REMOTE_CALLBACKS_INIT;
            callbacks.transfer_progress = progress_cb;
            callbacks.payload = &log;
            opts.version = GIT_SUBMODULE_UPDATE_OPTIONS_VERSION;
            opts.fetch_opts = GIT_FETCH_OPTIONS_INIT;
            opts.fetch_opts.callbacks = callbacks;
            opts.fetch_opts.version = GIT_FETCH_OPTIONS_VERSION;
            opts.checkout_opts = GIT_CHECKOUT_OPTIONS_INIT;
            opts.checkout_opts.checkout_strategy = GIT_CHECKOUT_SAFE;

            // Update submodule
            if (git_submodule_update(sm, 1, &opts) != 0) {
                const git_error* e = git_error_last();
                log->append("Failed to update submodule " + std::string(name) + ": " +
                            (e && e->message ? e->message : "unknown") + "\n");
            } else {
                log->append("Updated submodule: " + std::string(name) + "\n");
            }

            // Open the submodule repository
            git_repository* subrepo = nullptr;
            if (git_submodule_open(&subrepo, sm) != 0) {
                log->append("Failed to open submodule repository: " + std::string(name) + "\n");
                return 0; // Continue with other submodules
            }

            // Recurse into nested submodules
            // Pass the same lambda as the callback by casting it to std::function
            if (git_submodule_foreach(subrepo, submodule_trampoline, &submodule_callback) != 0) {
                const git_error* e = git_error_last();
                log->append("Failed to iterate nested submodules in " + std::string(name) + ": " +
                            (e && e->message ? e->message : "unknown") + "\n");
            }

            git_repository_free(subrepo);
            return 0;
        };

        // Start processing submodules with the top-level repository
        if (git_submodule_foreach(repo, submodule_trampoline, &submodule_callback) != 0) {
            const git_error* e = git_error_last();
            log->append("Failed to iterate over submodules: " +
                        std::string(e && e->message ? e->message : "unknown") + "\n");
        }

        git_remote_free(remote);
        git_repository_free(repo);
    }
}

/**
 * parse_version(...) from debian/changelog
 */
std::string parse_version(const fs::path &changelog_path) {
    if (!fs::exists(changelog_path)) {
        throw std::runtime_error("Changelog not found: " + changelog_path.string());
    }
    std::ifstream infile(changelog_path);
    if (!infile.is_open()) {
        throw std::runtime_error("Cannot open changelog: " + changelog_path.string());
    }
    std::string line;
    std::regex version_regex("^\\S+ \\(([^)]+)\\) .+");
    while (std::getline(infile, line)) {
        std::smatch match;
        if (std::regex_match(line, match, version_regex)) {
            if (match.size() >= 2) {
                std::string full_version = match[1].str();
                auto dash_pos = full_version.find('-');
                if (dash_pos != std::string::npos) {
                    return full_version.substr(0, dash_pos);
                } else {
                    return full_version;
                }
            }
        }
    }
    throw std::runtime_error("parse_version: can't parse debian/changelog");
}

/**
 * update_changelog with dch ...
 */
void update_changelog(const fs::path &packaging_dir,
                      const std::string &release,
                      const std::string &new_version,
                      const std::string &ppa_suffix,
                      std::shared_ptr<Log> log)
{
    std::vector<std::string> dch_cmd {
        "dch", "--distribution", release,
        "--newversion", new_version + "-0ubuntu0~ppa" + ppa_suffix,
        "--urgency", "low",
        "CI upload."
    };
    if (run_command(dch_cmd, packaging_dir, false, log)) {
        log->append("dch: updated changelog for " + release);
    } else {
        log->append("dch: failed for release " + release);
    }
}

/**
 * debuild_package ...
 */
void CiLogic::debuild_package(const fs::path &packaging_dir, std::shared_ptr<Log> log) {
    std::vector<std::string> cmd {
        "debuild",
        "--no-lintian",
        "-S",
        "-d",
        "-sa"
    };

    if (run_command(cmd, packaging_dir, false, log)) {
        log->append("debuild OK in " + packaging_dir.string() + "\n");
    } else {
        cmd.emplace_back("-nc");
        log->append("debuild failed in " + packaging_dir.string() +
                    " - trying again without cleaning\n");
        if (run_command(cmd, packaging_dir, false, log)) {
            log->append("debuild without cleaning OK in " + packaging_dir.string() + "\n");
        } else {
            log->append("debuild failed in " + packaging_dir.string() + "\n");
        }
    }
}

/**
 * collect_changes_files from build_output
 */
std::vector<std::string> collect_changes_files(const std::string &repo_name,
                                               const std::string &version)
{
    fs::path outdir = "/srv/lubuntu-ci/repos/build_output";
    fs::create_directories(outdir);
    std::vector<std::string> results;

    std::string prefix = repo_name + "_" + version;
    for (auto &entry : fs::directory_iterator(outdir)) {
        std::string filename = entry.path().filename().string();
        if (filename.rfind(prefix, 0) == 0
            && filename.size() >= 16
            && filename.substr(filename.size() - 15) == "_source.changes")
        {
            results.push_back(entry.path().string());
        }
    }
    if (results.empty()) {
        throw std::runtime_error("No .changes found for " + repo_name);
    }
    return results;
}

/**
 * reset_changelog to HEAD content
 */
static void reset_changelog(const fs::path &repo_dir, const fs::path &changelog_path) {
    git_repository *repo = nullptr;
    if (git_repository_open(&repo, repo_dir.c_str()) != 0) {
        const git_error *e = git_error_last();
        throw std::runtime_error(std::string("reset_changelog: open failed: ")
                                 + (e && e->message ? e->message : "???"));
    }
    git_reference *head_ref = nullptr;
    if (git_repository_head(&head_ref, repo) != 0) {
        const git_error *e = git_error_last();
        git_repository_free(repo);
        throw std::runtime_error(std::string("reset_changelog: repository_head: ")
                                 + (e && e->message ? e->message : "???"));
    }
    git_commit *commit = nullptr;
    if (git_reference_peel((git_object**)&commit, head_ref, GIT_OBJECT_COMMIT) != 0) {
        const git_error *e = git_error_last();
        git_reference_free(head_ref);
        git_repository_free(repo);
        throw std::runtime_error(std::string("reset_changelog: peel HEAD: ")
                                 + (e && e->message ? e->message : "???"));
    }
    git_tree *tree = nullptr;
    if (git_commit_tree(&tree, commit) != 0) {
        const git_error *e = git_error_last();
        git_commit_free(commit);
        git_reference_free(head_ref);
        git_repository_free(repo);
        throw std::runtime_error(std::string("reset_changelog: commit_tree: ")
                                 + (e && e->message ? e->message : "???"));
    }
    std::error_code ec;
    auto rel_path = fs::relative(changelog_path, repo_dir, ec);
    if (ec) {
        git_tree_free(tree);
        git_commit_free(commit);
        git_reference_free(head_ref);
        git_repository_free(repo);
        throw std::runtime_error("reset_changelog: relative path error: " + ec.message());
    }
    git_tree_entry *entry = nullptr;
    if (git_tree_entry_bypath(&entry, tree, rel_path.string().c_str()) != 0) {
        git_tree_free(tree);
        git_commit_free(commit);
        git_reference_free(head_ref);
        git_repository_free(repo);
        throw std::runtime_error("reset_changelog: cannot find debian/changelog in HEAD");
    }
    git_blob *blob = nullptr;
    if (git_tree_entry_to_object((git_object**)&blob, repo, entry) != 0) {
        git_tree_entry_free(entry);
        git_tree_free(tree);
        git_commit_free(commit);
        git_reference_free(head_ref);
        git_repository_free(repo);
        const git_error *e = git_error_last();
        throw std::runtime_error(std::string("reset_changelog: cannot get blob: ")
                                 + (e && e->message ? e->message : "???"));
    }
    const char *content = (const char*)git_blob_rawcontent(blob);
    size_t sz = git_blob_rawsize(blob);
    {
        std::ofstream out(changelog_path, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            git_blob_free(blob);
            git_tree_entry_free(entry);
            git_tree_free(tree);
            git_commit_free(commit);
            git_reference_free(head_ref);
            git_repository_free(repo);
            throw std::runtime_error("reset_changelog: cannot open " + changelog_path.string());
        }
        out.write(content, sz);
    }
    git_blob_free(blob);
    git_tree_entry_free(entry);
    git_tree_free(tree);
    git_commit_free(commit);
    git_reference_free(head_ref);
    git_repository_free(repo);
}

/**
 * pull_project:
 *   1. clone/fetch repos
 *   2. read HEAD commits
 *   3. sync
 */
bool CiLogic::pull_project(std::shared_ptr<PackageConf> &proj, std::shared_ptr<Log> log) {
    ensure_git_inited();

    log->append("Git initialized. Setting variables...\n");
    fs::path base_dir = "/srv/lubuntu-ci/repos";
    fs::path packaging_dir = base_dir / proj->package->name;
    fs::path upstream_dir  = base_dir / ("upstream-" + proj->package->name);

    // First do the actual pulls/fetches
    try {
        log->append("Cloning or fetching the upstream directory...\n");
        clone_or_fetch(upstream_dir, proj->package->upstream_url, std::nullopt, log);
        log->append("Cloning or fetching the packaging directory...\n");
        clone_or_fetch(packaging_dir, proj->package->packaging_url, proj->package->packaging_branch, log);
    } catch (...) {
        return false;
    }

    // Now read the HEAD commits and store them
    log->append("Fetching complete. Storing Git commit data...\n");
    if (!proj->packaging_commit) {
        proj->packaging_commit = std::make_unique<GitCommit>();
    }

    if (!proj->upstream_commit) {
        proj->upstream_commit = std::make_unique<GitCommit>();
    }
    *proj->packaging_commit = get_commit_from_pkg_repo(packaging_dir.string(), log);
    *proj->upstream_commit = get_commit_from_pkg_repo(upstream_dir.string(), log);
    proj->sync();

    log->append("Done!");
    return true;
}

/**
 * create_project_tarball
 */
bool CiLogic::create_project_tarball(std::shared_ptr<PackageConf> &proj, std::shared_ptr<Log> log) {
    log->append("Getting metadata for orig tarball...\n");
    fs::path base_dir = "/srv/lubuntu-ci/repos";
    fs::path packaging_dir = base_dir / proj->package->name;
    fs::path upstream_dir  = base_dir / ("upstream-" + proj->package->name);
    fs::path main_tarball = base_dir / (proj->package->name + "_MAIN.orig.tar.gz");
    fs::path copyright    = packaging_dir / "debian" / "copyright";

    std::vector<std::string> excludes;
    try {
        excludes = extract_files_excluded(copyright.string());
    } catch(...) {}
    excludes.emplace_back(".git/");
    log->append("Creating " + main_tarball.string() + " with the following exclusions:\n");
    for (auto exclude : excludes) { log->append(" - " + exclude + "\n"); }

    create_tarball(main_tarball.string(), upstream_dir.string(), excludes, log);

    log->append("Done!");
    return true;
}

/**
 * build_project
 */
std::tuple<bool, std::set<std::string>> CiLogic::build_project(std::shared_ptr<PackageConf> proj, std::shared_ptr<Log> log) {
    log->append("Building: " + proj->package->name + ", initializing...\n");
    std::set<std::string> changes_files;
    try {
        fs::path base_dir = "/srv/lubuntu-ci/repos";
        fs::path packaging_dir = base_dir / proj->package->name;
        fs::path changelog = packaging_dir / "debian" / "changelog";
        std::string base_ver = parse_version(changelog);
        std::string current_time = get_current_utc_time("%Y%m%d%H%M");
        std::string base_git_ver = base_ver + "+git" + current_time;

        fs::path working_dir;
        if (proj->package->large) {
            working_dir = "/srv/lubuntu-ci/repos/build_output/.tmp.build."
                          + proj->package->name + "_" + base_git_ver;
        } else {
            working_dir = create_temp_directory();
        }

        log->append("  => " + proj->package->name + " for " + proj->release->codename);
        proj->upstream_version = base_git_ver + "~" + proj->release->codename;
        sync(proj);

        // Update changelog for this release
        update_changelog(packaging_dir, proj->release->codename, proj->upstream_version, std::to_string(proj->ppa_revision), log);
        log->append("Changelog updated, copying the packaging...");

        // Now copy entire packaging into a subfolder
        fs::path dest_dir = working_dir / (proj->package->name + "-" + proj->upstream_version);
        copy_directory(packaging_dir, dest_dir);
        log->append("Copied packaging to " + dest_dir.string() + ", copying tarball...");

        // Reset changelog after dchd$ (so local changes aren't committed)
        reset_changelog(packaging_dir.parent_path() / proj->package->name, changelog);
        log->append("Reset debian/changelog to HEAD...");

        setenv("DEBFULLNAME", "Lugito", 1);
        setenv("DEBEMAIL", "info@lubuntu.me", 1);

        // Copy main tarball in place
        fs::path main_tarball = base_dir / (proj->package->name + "_MAIN.orig.tar.gz");
        size_t epoch_pos = proj->upstream_version.find(':');
        std::string tar_version = (epoch_pos != std::string::npos)
                                  ? proj->upstream_version.substr(epoch_pos + 1)
                                  : proj->upstream_version;
        fs::path tar_name = proj->package->name + "_" + tar_version + ".orig.tar.gz";
        fs::path tar_dest = working_dir / tar_name;
        fs::copy(main_tarball, tar_dest, fs::copy_options::overwrite_existing);
        log->append("Copied tarball to " + tar_dest.string() + ", building...");

        // Build
        debuild_package(dest_dir, log);

        log->append("Source package built! Moving build artifacts...");

        // Move build products to build_output
        fs::path build_out = "/srv/lubuntu-ci/repos/build_output";
        fs::create_directories(build_out);
        for (auto &entry : fs::directory_iterator(working_dir)) {
            if (fs::is_regular_file(entry)) {
                try {
                    fs::rename(entry.path(), build_out / entry.path().filename());
                } catch(const fs::filesystem_error &fe) {
                    if (fe.code() == std::errc::cross_device_link) {
                        fs::copy_file(
                            entry.path(),
                            build_out / entry.path().filename(),
                            fs::copy_options::overwrite_existing
                        );
                        fs::remove(entry.path());
                    } else {
                        throw;
                    }
                }
            }
        }

        // Collect the changes files for this release
        auto changes = collect_changes_files(proj->package->name, tar_version);
        for (auto &c : changes) {
            changes_files.insert(c);
        }
        log->append("Build done for " + proj->release->codename + "\n");

        fs::remove_all(working_dir);
    } catch(std::exception &ex) {
        log->append("Build fail for " + proj->package->name + ": " + ex.what() + "\n");
        throw;
    }
    std::tuple<bool, std::set<std::string>> result = {true, changes_files};
    return result;
}

/**
 * upload_and_lint
 */
bool CiLogic::upload_and_lint(std::shared_ptr<PackageConf> &proj,
                              const std::set<std::string> changes_files,
                              bool skip_dput,
                              std::shared_ptr<Log> log) {
    if (skip_dput) {
        log->append("Skipping dput as requested.\n");
        return true;
    }
    if (changes_files.empty()) {
        log->append("No changes to upload for " + proj->package->name + "\n");
        return false;
    }
    std::string base_target = proj->branch->upload_target;
    for (auto &chfile : changes_files) {
        bool uploaded = false;
        std::string t = base_target;
        for (int attempt = 1; attempt <= 5 && !uploaded; attempt++) {
            log->append("dput attempt " + std::to_string(attempt)
                        + ": " + chfile + " => " + t + "\n");
            std::vector<std::string> cmd {"dput", t, chfile};
            try {
                if (!run_command(cmd, std::nullopt, false, log)) {
                    log->append("dput to " + t + " returned error!\n");
                } else {
                    log->append("Uploaded " + chfile + " => " + t + "\n");
                    uploaded = true;
                }
            } catch(std::exception &ex) {
                log->append("Upload error: " + std::string(ex.what()) + "\n");
            }
            if (!uploaded) {
                // If failed, try SSH variant
                t = proj->branch->upload_target_ssh;
            }
        }
    }
    return true;
}

/**
 * do_summary
 */
void CiLogic::do_summary(bool skip_cleanup) {
    log_info("Summary/cleanup stage");
    if (!skip_cleanup) {
        fs::path outdir = "/srv/lubuntu-ci/repos/build_output";
        fs::remove_all(outdir);
        log_info("Cleaned build output in " + outdir.string());
    } else {
        log_info("skip_cleanup => leaving build_output alone.");
    }
}

/**
 * Orchestrate entire pipeline
 */
void CiLogic::process_entire_pipeline(std::shared_ptr<PackageConf> &proj,
                                      bool skip_dput,
                                      bool skip_cleanup)
{
    try {
        bool pull_success = pull_project(proj);
        bool tarball_success = create_project_tarball(proj);
        const auto [build_success, changes_files] = build_project(proj);
        upload_and_lint(proj, changes_files, skip_dput);
        do_summary(skip_cleanup);
        log_info("Pipeline done for " + proj->package->name);
    } catch(std::exception &ex) {
        log_error("Pipeline fail for " + proj->package->name + ": " + ex.what());
    }
}

/**
 * get_config
 */
std::vector<std::shared_ptr<PackageConf>> CiLogic::get_config(const std::string &repo_name,
                                                              int page,
                                                              int per_page,
                                                              const std::string &sort_by,
                                                              const std::string &sort_order) {
    // If we have page/per_page/sort_by/sort_order, do a sort & pagination
    if (page != 0 && per_page != 0 && (!sort_by.empty()) && (!sort_order.empty())) {
        auto getComparator = [](const std::string& sort_by, const std::string& order) {
            return [sort_by, order](const std::shared_ptr<PackageConf>& a, const std::shared_ptr<PackageConf>& b) {
                if (sort_by == "name") {
                    return (order == "asc")
                        ? (a->package->name < b->package->name)
                        : (a->package->name > b->package->name);
                } else if (sort_by == "branch_name") {
                    return (order == "asc")
                        ? (a->branch->name < b->branch->name)
                        : (a->branch->name > b->branch->name);
                } else if (sort_by == "packaging_commit") {
                    if (a->packaging_commit && b->packaging_commit) {
                        auto time_a = a->packaging_commit->commit_datetime.get_sys_time();
                        auto time_b = b->packaging_commit->commit_datetime.get_sys_time();
                        return (order == "asc") ? (time_a < time_b) : (time_a > time_b);
                    } else {
                        // fallback comparison
                        return (order == "asc")
                            ? (a->package->name < b->package->name)
                            : (a->package->name > b->package->name);
                    }
                } else if (sort_by == "upstream_commit") {
                    if (a->upstream_commit && b->upstream_commit) {
                        auto time_a = a->upstream_commit->commit_datetime.get_sys_time();
                        auto time_b = b->upstream_commit->commit_datetime.get_sys_time();
                        return (order == "asc") ? (time_a < time_b) : (time_a > time_b);
                    } else {
                        // fallback comparison
                        return (order == "asc")
                            ? (a->package->name < b->package->name)
                            : (a->package->name > b->package->name);
                    }
                } else if (sort_by == "build_status") {
                    int a_successful_task_count = a->successful_task_count();
                    int b_successful_task_count = b->successful_task_count();
                    if (a_successful_task_count != b_successful_task_count) {
                        return (order == "asc")
                            ? (a_successful_task_count < b_successful_task_count)
                            : (a_successful_task_count > b_successful_task_count);
                    } else {
                        return (order == "asc")
                            ? (a->total_task_count() < b->total_task_count())
                            : (a->total_task_count() > b->total_task_count());
                    }
                }
                // if invalid sort_by
                return false;
            };
        };
        auto paginate = [getComparator](std::vector<std::shared_ptr<PackageConf>>& items,
                                        int page, int per_page,
                                        const std::string& sort_by,
                                        const std::string& sort_order) {
            std::sort(items.begin(), items.end(), getComparator(sort_by, sort_order));
            int startIdx = (page - 1) * per_page;
            int endIdx   = std::min(startIdx + per_page, static_cast<int>(items.size()));
            if (startIdx >= (int)items.size()) {
                return std::vector<std::shared_ptr<PackageConf>>();
            }
            return std::vector<std::shared_ptr<PackageConf>>(items.begin() + startIdx, items.begin() + endIdx);
        };

        auto copy_confs = get_packageconfs();
        return paginate(copy_confs, page, per_page, sort_by, sort_order);
    }
    // If just repo_name is provided, filter by that. If empty, return all
    else if (!repo_name.empty()) {
        std::vector<std::shared_ptr<PackageConf>> filtered;
        for (const auto &pc : get_packageconfs()) {
            if (pc->package->name == repo_name) {
                filtered.push_back(pc);
            }
        }
        return filtered;
    }

    // Otherwise return everything
    return get_packageconfs();
}

std::string CiLogic::queue_pull_tarball(std::vector<std::shared_ptr<PackageConf>> repos,
                                        std::unique_ptr<TaskQueue>& task_queue,
                                        std::shared_ptr<std::map<std::string, std::shared_ptr<JobStatus>>> job_statuses) {
    std::string msg;
    std::map<std::string, std::shared_ptr<package_conf_item>> encountered_items;
    std::mutex task_assignment_mutex;

    try {
        for (auto r : repos) {
            bool is_ghost_pull = false;

            // Attempt to find if we've seen this package->name before
            std::lock_guard<std::mutex> lock(task_assignment_mutex);
            auto found_it = encountered_items.find(r->package->name);
            std::shared_ptr<package_conf_item> new_item = std::make_shared<package_conf_item>();
            if (found_it != encountered_items.end()) {
                is_ghost_pull = true;

                r->assign_task(job_statuses->at("pull"), found_it->second->first_pull_task, r);
                r->assign_task(job_statuses->at("tarball"), found_it->second->first_tarball_task, r);
                r->packaging_commit = found_it->second->packaging_commit;
                r->upstream_commit = found_it->second->upstream_commit;
                sync(r);

                continue;
            }

            task_queue->enqueue(
                job_statuses->at("pull"),
                [this, r](std::shared_ptr<Log> log) mutable {
                    pull_project(r, log);
                },
                r
            );
            new_item->first_pull_task = r->get_task_by_jobstatus(job_statuses->at("pull"));

            task_queue->enqueue(
                job_statuses->at("tarball"),
                [this, r](std::shared_ptr<Log> log) mutable {
                    create_project_tarball(r, log);
                },
                r
            );
            new_item->first_tarball_task = r->get_task_by_jobstatus(job_statuses->at("tarball"));

            new_item->first_pkgconf = r;

            new_item->packaging_commit = r->packaging_commit;
            new_item->upstream_commit = r->upstream_commit;
            encountered_items[r->package->name] = new_item;
        }
        msg = "Succeeded";
    } catch (...) {
        msg = "Failed";
    }

    return msg;
}

std::string CiLogic::queue_build_upload(std::vector<std::shared_ptr<PackageConf>> repos,
                                        std::unique_ptr<TaskQueue>& task_queue,
                                        std::shared_ptr<std::map<std::string, std::shared_ptr<JobStatus>>> job_statuses) {
    std::string msg;

    try {
        for (auto r : repos) {
            task_queue->enqueue(
                job_statuses->at("source_build"),
                [this, r, &task_queue, job_statuses](std::shared_ptr<Log> log) mutable {
                    auto [build_ok, changes_files] = build_project(r, log);
                    if (build_ok) {
                        task_queue->enqueue(
                            job_statuses->at("upload"),
                            [this, r, changes_files](std::shared_ptr<Log> log) mutable {
                                bool upload_ok = upload_and_lint(r, changes_files, false, log);
                                (void)upload_ok;
                            },
                            r
                        );
                    }
                },
                r
            );
        }
        msg = "Succeeded";
    } catch (...) {
        msg = "Failed";
    }

    return msg;
}

std::shared_ptr<std::map<std::string, std::shared_ptr<JobStatus>>> CiLogic::get_job_statuses() {
    if (_cached_job_statuses != nullptr) { return _cached_job_statuses; }

    static const auto statuses = std::make_shared<std::map<std::string, std::shared_ptr<JobStatus>>>(
        std::map<std::string, std::shared_ptr<JobStatus>>{
            {"pull", std::make_shared<JobStatus>(JobStatus(1))},
            {"tarball", std::make_shared<JobStatus>(JobStatus(2))},
            {"source_build", std::make_shared<JobStatus>(JobStatus(3))},
            {"upload", std::make_shared<JobStatus>(JobStatus(4))},
            {"source_check", std::make_shared<JobStatus>(JobStatus(5))},
            {"build_check", std::make_shared<JobStatus>(JobStatus(6))},
            {"lintian", std::make_shared<JobStatus>(JobStatus(7))},
            {"britney", std::make_shared<JobStatus>(JobStatus(8))}
        }
    );

    _cached_job_statuses = statuses;
    return statuses;
}

std::vector<std::shared_ptr<PackageConf>> CiLogic::get_packageconfs() {
    std::lock_guard<std::mutex> lock(packageconfs_mutex_);
    return packageconfs;
}

std::shared_ptr<PackageConf> CiLogic::get_packageconf_by_id(int id) {
    std::lock_guard<std::mutex> lock(packageconfs_mutex_);
    auto it = std::ranges::find_if(packageconfs, [id](auto pkgconf) {
        return pkgconf->id == id;
    });

    if (it != packageconfs.end()) {
        return *it;
    }
    throw std::runtime_error("PackageConf not found");
}

std::vector<std::shared_ptr<PackageConf>> CiLogic::get_packageconfs_by_ids(std::set<int> ids) {
    std::lock_guard<std::mutex> lock(packageconfs_mutex_);

    auto filtered_view = packageconfs
        | std::views::filter([&](auto pkgconf) {
            return ids.contains(pkgconf->id);
          });

    return std::vector<std::shared_ptr<PackageConf>>(filtered_view.begin(), filtered_view.end());
}

void CiLogic::set_packageconfs(std::vector<std::shared_ptr<PackageConf>> _pkgconfs) {
    std::lock_guard<std::mutex> lock(packageconfs_mutex_);
    packageconfs = _pkgconfs;
}

void CiLogic::sync(std::shared_ptr<PackageConf> pkgconf) {
    std::lock_guard<std::mutex> lock(packageconfs_mutex_);
    pkgconf->sync();
}

/**
 * Stub logs
 */
std::string CiLogic::get_logs_for_repo_conf(int package_conf_id) {
    return "Not implemented";
}
