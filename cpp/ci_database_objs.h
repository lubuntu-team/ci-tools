// Copyright (C) 2025 Simon Quigley <tsimonq2@ubuntu.com>
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

#ifndef CI_DATABASE_OBJS_H
#define CI_DATABASE_OBJS_H

#include <chrono>
#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <mutex>

#include <QDateTime>
#include <QSqlDatabase>
#include <yaml-cpp/yaml.h>

#include "common.h"

class Person {
public:
    int id;
    std::string username;
    std::string logo_url;

    Person(int id = 0, const std::string username = "", const std::string logo_url = "");
};

class Release {
public:
    int id;
    int version;
    std::string codename;
    bool isDefault;

    Release(int id = 0, int version = 0, const std::string& codename = "", bool isDefault = false);
    std::vector<Release> get_releases(QSqlDatabase& p_db);
    Release get_release_by_id(QSqlDatabase& p_db, int id);
    bool set_releases(QSqlDatabase& p_db, YAML::Node& releases);
};

class Package {
public:
    int id;
    std::string name;
    bool large;
    std::string upstream_browser;
    std::string packaging_browser;
    std::string upstream_url;
    std::string packaging_branch;
    std::string packaging_url;

    Package(int id = 0, const std::string& name = "", bool large = false, const std::string& upstream_url = "", const std::string& packaging_branch = "", const std::string& packaging_url = "");
    std::vector<Package> get_packages(QSqlDatabase& p_db);
    Package get_package_by_id(QSqlDatabase& p_db, int id);
    bool set_packages(QSqlDatabase& p_db, YAML::Node& packages);

private:
    std::string transform_url(const std::string& url);
};

class Branch {
public:
    int id;
    std::string name;
    std::string upload_target;
    std::string upload_target_ssh;

    Branch(int id = 0, const std::string& name = "", const std::string& upload_target = "", const std::string& upload_target_ssh = "");
    std::vector<Branch> get_branches(QSqlDatabase& p_db);
    Branch get_branch_by_id(QSqlDatabase& p_db, int id);
};

class GitCommit {
public:
    int id = 0;
    std::string commit_hash;
    std::string commit_summary;
    std::string commit_message;
    std::chrono::zoned_time<std::chrono::seconds> commit_datetime;
    std::string commit_author;
    std::string commit_committer;

    GitCommit(
        QSqlDatabase& p_db,
        const std::string& commit_hash = "",
        const std::string& commit_summary = "",
        const std::string& commit_message = "",
        const std::chrono::zoned_time<std::chrono::seconds>& commit_datetime = std::chrono::zoned_time<std::chrono::seconds>(),
        const std::string& commit_author = "",
        const std::string& commit_committer = ""
    );
    GitCommit(
        const int id = 0,
        const std::string& commit_hash = "",
        const std::string& commit_summary = "",
        const std::string& commit_message = "",
        const std::chrono::zoned_time<std::chrono::seconds>& commit_datetime = std::chrono::zoned_time<std::chrono::seconds>(),
        const std::string& commit_author = "",
        const std::string& commit_committer = ""
    );

    GitCommit get_commit_by_id(QSqlDatabase& p_db, int id);
    std::optional<GitCommit> get_commit_by_hash(QSqlDatabase& p_db, const std::string commit_hash);

private:
    std::chrono::zoned_time<std::chrono::seconds> convert_timestr_to_zonedtime(const std::string& datetime_str);
};

class JobStatus {
public:
    int id;
    int build_score;
    std::string name;
    std::string display_name;

    JobStatus(QSqlDatabase& p_db, int id);
};

class PackageConf {
public:
    int id = 0;
    std::shared_ptr<Package> package;
    std::shared_ptr<Release> release;
    std::shared_ptr<Branch> branch;
    std::shared_ptr<GitCommit> packaging_commit = std::make_shared<GitCommit>();
    std::shared_ptr<GitCommit> upstream_commit = std::make_shared<GitCommit>();
    std::string upstream_version;
    int ppa_revision = 1;

    bool operator<(const PackageConf& other) const {
        if (package->id != other.package->id)
            return package->id < other.package->id;
        if (release->id != other.release->id)
            return release->id < other.release->id;
        if (branch->id != other.branch->id)
            return branch->id < other.branch->id;
        return id < other.id;
    }
    bool operator==(const PackageConf& other) const {
        // Intentionally leave out our ID
        return package->id == other.package->id &&
               release->id == other.release->id &&
               branch->id == other.branch->id;
    }

    PackageConf(int id = 0, std::shared_ptr<Package> package = NULL, std::shared_ptr<Release> release = NULL, std::shared_ptr<Branch> branch = NULL,
                std::shared_ptr<GitCommit> packaging_commit = NULL, std::shared_ptr<GitCommit> upstream_commit = NULL);
    std::vector<std::shared_ptr<PackageConf>> get_package_confs(QSqlDatabase& p_db, std::map<std::string, std::shared_ptr<JobStatus>> jobstatus_map);
    std::vector<std::shared_ptr<PackageConf>> get_package_confs_by_package_name(QSqlDatabase& p_db,
                                                                                std::vector<std::shared_ptr<PackageConf>> packageconfs,
                                                                                const std::string& package_name);
    void assign_task(std::shared_ptr<JobStatus> jobstatus, std::shared_ptr<Task> task_ptr, std::weak_ptr<PackageConf> packageconf_ptr);
    int successful_task_count();
    int total_task_count();
    std::shared_ptr<Task> get_task_by_jobstatus(std::shared_ptr<JobStatus> jobstatus);
    bool set_package_confs(QSqlDatabase& p_db);
    bool set_commit_id(const std::string& _commit_id = "");
    bool set_commit_time(const std::chrono::zoned_time<std::chrono::seconds>& _commit_time = std::chrono::zoned_time<std::chrono::seconds>{});
    void sync(QSqlDatabase& p_db);
    bool can_check_source_upload();
    bool can_check_builds();

    struct PackageConfPlain {
        int package_id;
        int release_id;
        int branch_id;
        bool operator<(const PackageConf::PackageConfPlain& other) const {
            if (package_id != other.package_id)
                return package_id < other.package_id;
            if (release_id != other.release_id)
                return release_id < other.release_id;
            return branch_id < other.branch_id;
        }

        bool operator==(const PackageConf::PackageConfPlain& other) const {
            return package_id == other.package_id &&
                   release_id == other.release_id &&
                   branch_id == other.branch_id;
        }
    };

private:
    std::unordered_map<std::shared_ptr<JobStatus>, std::shared_ptr<Task>> jobstatus_task_map_;
    std::unique_ptr<std::mutex> task_mutex_ = std::make_unique<std::mutex>();
};

class Task {
public:
    int id;
    int build_score = 0;
    bool successful;
    std::int64_t queue_time = 0;
    std::int64_t start_time = 0;
    std::int64_t finish_time = 0;
    std::function<void(std::shared_ptr<Log> log)> func;
    std::shared_ptr<Log> log;
    std::shared_ptr<JobStatus> jobstatus;
    std::weak_ptr<PackageConf> parent_packageconf;
    bool is_running;

    Task(QSqlDatabase& p_db, std::shared_ptr<JobStatus> jobstatus, std::int64_t time, std::shared_ptr<PackageConf> packageconf);
    Task();

    std::set<std::shared_ptr<Task>> get_completed_tasks(QSqlDatabase& p_db, std::vector<std::shared_ptr<PackageConf>> packageconfs, std::map<std::string, std::shared_ptr<JobStatus>> job_statuses, int page, int per_page);
    void save(QSqlDatabase& p_db, int _packageconf_id = 0);

    std::shared_ptr<PackageConf> get_parent_packageconf() const {
        return parent_packageconf.lock();
    }

    struct TaskComparator {
        bool operator()(const std::shared_ptr<Task>& lhs, const std::shared_ptr<Task>& rhs) const {
            return Task::compare(lhs, rhs);
        }
    };

    // Custom comparator for task ordering
    bool operator<(const Task& other) const {
        if (build_score != other.build_score) {
            return build_score < other.build_score;
        } else if (queue_time != other.queue_time) {
            return queue_time < other.queue_time;
        } else if (start_time != other.start_time) {
            return start_time < other.start_time;
        } else if (finish_time != other.finish_time) {
            return finish_time < other.finish_time;
        }
        return true;
    }

    bool operator<(const std::shared_ptr<Task>& other) const {
        if (build_score != other->build_score) {
            return build_score < other->build_score;
        } else if (queue_time != other->queue_time) {
            return queue_time < other->queue_time;
        } else if (start_time != other->start_time) {
            return start_time < other->start_time;
        } else if (finish_time != other->finish_time) {
            return finish_time < other->finish_time;
        }
        return true;
    }

    static bool compare(const std::shared_ptr<Task>& lhs, const std::shared_ptr<Task>& rhs);
};

inline size_t qHash(const PackageConf::PackageConfPlain& key, size_t seed = 0) {
    size_t res = 0;
    res ^= std::hash<int>()(key.package_id) + 0x9e3779b9 + (res << 6) + (res >> 2);
    res ^= std::hash<int>()(key.release_id) + 0x9e3779b9 + (res << 6) + (res >> 2);
    res ^= std::hash<int>()(key.branch_id) + 0x9e3779b9 + (res << 6) + (res >> 2);
    return res;
}

#endif // CI_DATABASE_OBJS_H

