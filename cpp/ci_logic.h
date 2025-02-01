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

#ifndef CI_LOGIC_H
#define CI_LOGIC_H

#include "ci_database_objs.h"
#include "task_queue.h"

#include <string>
#include <vector>
#include <optional>
#include <filesystem>
#include <mutex>
#include <queue>
#include <thread>
#include <functional>
#include <condition_variable>

#include <QSqlDatabase>
#include <yaml-cpp/yaml.h>

namespace fs = std::filesystem;

struct CiProject {
    std::string name;
    std::string version;
    std::string time;
    std::string upload_target;
    std::string upstream_url;
    std::string packaging_url;
    std::optional<std::string> packaging_branch;
    fs::path main_tarball;
    bool large = false;
    // These get populated during build:
    std::vector<std::string> changes_files;
    std::vector<std::string> devel_changes_files;
};

class CiLogic {
public:
    // Initialize global config and database
    void init_global();

    // Load YAML config from a given path
    YAML::Node load_yaml_config(const fs::path &config_path);

    // Convert a YAML node to a CiProject
    CiProject yaml_to_project(const YAML::Node &pkg_node);

    // Pipeline functions
    bool pull_project(std::shared_ptr<PackageConf> &proj, std::shared_ptr<Log> log = nullptr);
    bool create_project_tarball(std::shared_ptr<PackageConf> &proj, std::shared_ptr<Log> log = nullptr);
    std::tuple<bool, std::set<std::string>> build_project(std::shared_ptr<PackageConf> proj, std::shared_ptr<Log> log = nullptr);
    bool upload_and_lint(std::shared_ptr<PackageConf> &proj,
                           const std::set<std::string> changes_files,
                           bool skip_dput,
                           std::shared_ptr<Log> log = nullptr);

    // Summary & cleanup
    void do_summary(bool skip_cleanup);

    // Orchestrate entire pipeline
    void process_entire_pipeline(std::shared_ptr<PackageConf> &proj,
                                 bool skip_dput,
                                 bool skip_cleanup);

    // Retrieve PackageConf entries (with optional pagination/sorting)
    std::vector<std::shared_ptr<PackageConf>> get_config(const std::string &repo_name = "",
                                                         int page = 0,
                                                         int per_page = 0,
                                                         const std::string &sort_by = "",
                                                         const std::string &sort_order = "");

    // Enqueue a task (wrapper)
    void enqueue(std::function<void()> task);

    // Job status and PackageConf getters
    std::shared_ptr<std::map<std::string, std::shared_ptr<JobStatus>>> get_job_statuses();
    std::vector<std::shared_ptr<PackageConf>> get_packageconfs();
    std::shared_ptr<PackageConf> get_packageconf_by_id(int id);
    std::vector<std::shared_ptr<PackageConf>> get_packageconfs_by_ids(std::set<int> ids);
    void set_packageconfs(std::vector<std::shared_ptr<PackageConf>> _pkgconfs);
    void sync(std::shared_ptr<PackageConf> pkgconf);

    // Queue tasks
    std::string queue_pull_tarball(std::vector<std::shared_ptr<PackageConf>> repos,
                                   std::unique_ptr<TaskQueue>& task_queue,
                                   std::shared_ptr<std::map<std::string, std::shared_ptr<JobStatus>>> job_statuses);
    std::string queue_build_upload(std::vector<std::shared_ptr<PackageConf>> repos,
                                   std::unique_ptr<TaskQueue>& task_queue,
                                   std::shared_ptr<std::map<std::string, std::shared_ptr<JobStatus>>> job_statuses);

    // Get a task’s log
    std::string get_task_log(int task_id);

    std::vector<std::shared_ptr<PackageConf>> list_known_repos(int page = 0,
        int per_page = 0,
        const std::string &sort_by = "",
        const std::string &sort_order = "");
    bool pull_repo_by_name(const std::string &repo_name, std::shared_ptr<Log> log = nullptr);
    bool create_project_tarball_by_name(const std::string &repo_name, std::shared_ptr<Log> log = nullptr);
    bool build_repo_by_name(const std::string &repo_name, std::shared_ptr<Log> log = nullptr);

    // These come from the config/DB
    std::vector<Release> releases;
    std::vector<Package> packages;
    std::vector<Branch> branches;

private:
    void debuild_package(const fs::path &packaging_dir, std::shared_ptr<Log> log);

    QSqlDatabase p_db;
    mutable std::mutex packageconfs_mutex_;
    std::vector<std::shared_ptr<PackageConf>> packageconfs;
    std::shared_ptr<std::map<std::string, std::shared_ptr<JobStatus>>> _cached_job_statuses;

    struct package_conf_item {
        std::shared_ptr<PackageConf> first_pkgconf;
        std::shared_ptr<Task> first_pull_task = std::make_shared<Task>();
        std::shared_ptr<Task> first_tarball_task = std::make_shared<Task>();
        std::shared_ptr<GitCommit> packaging_commit = std::make_shared<GitCommit>();
        std::shared_ptr<GitCommit> upstream_commit = std::make_shared<GitCommit>();
    };
};

#endif // CI_LOGIC_H
