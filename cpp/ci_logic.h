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

// cpp/ci_logic.h
// [License Header as in original]

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

struct CiProject;

/**
 * Data describing one package to pull/build/etc.
 */
struct CiProject {
    std::string name;
    std::string version;
    std::string time;
    std::string upload_target;
    std::string upstream_url;
    std::string packaging_url;
    std::optional<std::string> packaging_branch;
    std::filesystem::path main_tarball;
    bool large = false;

    // These get populated during build
    std::vector<std::string> changes_files;
    std::vector<std::string> devel_changes_files;
};

class CiLogic {
    public:
        // Initialize global configurations
        void init_global();

        // Load YAML configuration from a given path
        YAML::Node load_yaml_config(const std::filesystem::path &config_path);

        // Convert a YAML node to a CiProject structure
        CiProject yaml_to_project(const YAML::Node &pkg_node);

        // Clone or fetch a git repository
        void clone_or_fetch(const std::filesystem::path &repo_dir, const std::string &repo_url, const std::optional<std::string> &branch, std::shared_ptr<Log> log = NULL);

        bool pull_project(std::shared_ptr<PackageConf> &proj, std::shared_ptr<Log> log = NULL);
        bool create_project_tarball(std::shared_ptr<PackageConf> &proj, std::shared_ptr<Log> log = NULL);
        std::tuple<bool, std::set<std::string>> build_project(std::shared_ptr<PackageConf> proj, std::shared_ptr<Log> log = NULL);
        bool upload_and_lint(std::shared_ptr<PackageConf> &proj, const std::set<std::string> changes_files, bool skip_dput, std::shared_ptr<Log> log = NULL);

        // Perform cleanup and summarize the build process
        void do_summary(bool skip_cleanup);

        // Process the entire pipeline for a given PackageConf ID
        void process_entire_pipeline(std::shared_ptr<PackageConf> &proj, bool skip_dput, bool skip_cleanup);

        // Retrieve all PackageConf entries from the database
        std::vector<std::shared_ptr<PackageConf>> get_config(const std::string &repo_name = "", int page = 0, int per_page = 0, const std::string& sort_by = "", const std::string& sort_order = "");

        // Function to enqueue tasks
        void enqueue(std::function<void()> task);

        // Fetch logs for a specific PackageConf ID
        std::string get_logs_for_repo_conf(int package_conf_id);

        std::map<std::string, std::shared_ptr<JobStatus>> get_job_statuses();
        std::vector<std::shared_ptr<PackageConf>> get_packageconfs();
        std::shared_ptr<PackageConf> get_packageconf_by_id(int id);
        std::vector<std::shared_ptr<PackageConf>> get_packageconfs_by_ids(std::set<int> ids);
        void set_packageconfs(std::vector<std::shared_ptr<PackageConf>> _pkgconfs);
        void sync(std::shared_ptr<PackageConf> pkgconf);

        QSqlDatabase get_thread_connection();

        std::string queue_pull_tarball(std::vector<std::shared_ptr<PackageConf>> repos,
                                       std::unique_ptr<TaskQueue>& task_queue,
                                       const std::map<std::string, std::shared_ptr<JobStatus>> job_statuses);

        std::vector<Release> releases;
        std::vector<Package> packages;
        std::vector<Branch> branches;

    private:
        // Initialize the database
        bool init_database(const QString& connectionName = "LubuntuCIConnection",
                           const QString& databasePath = "/srv/lubuntu-ci/repos/ci-tools/lubuntu_ci.db");

        void debuild_package(const fs::path &packaging_dir, std::shared_ptr<Log> log);

        QSqlDatabase p_db;

        mutable std::mutex connection_mutex_;
        mutable std::mutex packageconfs_mutex_;
        std::vector<std::shared_ptr<PackageConf>> packageconfs;
        std::map<std::string, std::shared_ptr<JobStatus>> _cached_job_statuses;

        struct package_conf_item {
            std::shared_ptr<PackageConf> first_pkgconf;
            std::shared_ptr<Task> first_pull_task = std::make_shared<Task>();
            std::shared_ptr<Task> first_tarball_task = std::make_shared<Task>();
            std::shared_ptr<GitCommit> packaging_commit = std::make_shared<GitCommit>();
            std::shared_ptr<GitCommit> upstream_commit = std::make_shared<GitCommit>();
        };
};

#endif // CI_LOGIC_H
