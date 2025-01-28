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
#include "git_common.h"

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

        // Reset changelog after dch (so pending changes aren't committed)
        reset_changelog(packaging_dir.parent_path() / proj->package->name, changelog);
        log->append("Reset debian/changelog to HEAD...");

        // Update changelog for this release
        update_changelog(packaging_dir, proj->release->codename, proj->upstream_version, std::to_string(proj->ppa_revision), log);
        log->append("Changelog updated, copying the packaging...");

        // Now copy entire packaging into a subfolder
        fs::path dest_dir = working_dir / (proj->package->name + "-" + proj->upstream_version);
        copy_directory(packaging_dir, dest_dir);
        log->append("Copied packaging to " + dest_dir.string() + ", copying tarball...");

        // Reset changelog after dch (so local changes aren't committed)
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
                    if (a->successful_task_count() != b->successful_task_count()) {
                        return (order == "asc")
                            ? (a->successful_task_count() < b->successful_task_count())
                            : (a->successful_task_count() > b->successful_task_count());
                    } else if (a->successful_or_pending_task_count() != b->successful_or_pending_task_count()) {
                        return (order == "asc")
                            ? (a->successful_or_pending_task_count() < b->successful_or_pending_task_count())
                            : (a->successful_or_pending_task_count() > b->successful_or_pending_task_count());
                    } else if (a->successful_or_queued_task_count() != b->successful_or_queued_task_count()) {
                        return (order == "asc")
                            ? (a->successful_or_queued_task_count() < b->successful_or_queued_task_count())
                            : (a->successful_or_queued_task_count() > b->successful_or_queued_task_count());
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
                                        std::shared_ptr<std::map<std::string, std::shared_ptr<JobStatus>>> job_statuses)
{
    std::string msg;
    std::map<std::string, std::shared_ptr<package_conf_item>> encountered_items;
    std::mutex task_assignment_mutex;

    try {
        for (auto &r : repos) {
            {
                std::lock_guard<std::mutex> lock(task_assignment_mutex);
                auto found_it = encountered_items.find(r->package->name);
                if (found_it != encountered_items.end()) {
                    // GHOST pull
                    auto existing_item = found_it->second;

                    // Assign tasks (reuse the same Task objects for "pull"/"tarball")
                    r->assign_task(job_statuses->at("pull"), existing_item->first_pull_task, r);
                    r->assign_task(job_statuses->at("tarball"), existing_item->first_tarball_task, r);

                    // Point packaging_commit/upstream_commit to the real pkgconf's pointers
                    r->packaging_commit = existing_item->first_pkgconf->packaging_commit;
                    r->upstream_commit  = existing_item->first_pkgconf->upstream_commit;
                    r->sync();
                    continue;
                }
            }
            // REAL pull
            auto new_item = std::make_shared<package_conf_item>();
            new_item->first_pkgconf = r;
            r->sync();

            // Enqueue "pull"
            task_queue->enqueue(
                job_statuses->at("pull"),
                [this, r](std::shared_ptr<Log> log) mutable {
                    pull_project(r, log);
                    r->sync();
                },
                r
            );

            {
                std::lock_guard<std::mutex> lock(task_assignment_mutex);
                new_item->first_pull_task = r->get_task_by_jobstatus(job_statuses->at("pull"));
            }

            // Enqueue "tarball"
            task_queue->enqueue(
                job_statuses->at("tarball"),
                [this, r](std::shared_ptr<Log> log) mutable {
                    create_project_tarball(r, log);
                    r->sync();
                },
                r
            );

            {
                std::lock_guard<std::mutex> lock(task_assignment_mutex);
                new_item->first_tarball_task = r->get_task_by_jobstatus(job_statuses->at("tarball"));
                encountered_items[r->package->name] = new_item;
            }

            r->sync();
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
