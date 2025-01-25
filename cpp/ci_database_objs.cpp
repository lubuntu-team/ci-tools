// Copyright (C) 2023-2025 Simon Quigley <tsimonq2@ubuntu.com>
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

#include "ci_database_objs.h"
#include "utilities.h"
#include "db_common.h"

#include <algorithm>
#include <ranges>
#include <regex>

#include <QDateTime>
#include <QSqlQuery>
#include <QSqlError>

// Person
// Minimal representation of a Launchpad Person
Person::Person(int id, const std::string username, const std::string logo_url)
    : id(id), username(username), logo_url(logo_url) {}

// End of Person
// Release
//
// We do not define any setter or getter functions here. It is assumed that the Release
// values will be created in batch, in a separate function, likely from the database
Release::Release(int id, int version, const std::string& codename, bool isDefault)
    : id(id), version(version), codename(codename), isDefault(isDefault) {}

std::vector<Release> Release::get_releases() {
    std::vector<Release> result;
    QString query_str = "SELECT id, version, codename, isDefault FROM release;";
    QSqlQuery query(query_str, get_thread_connection());
    while (query.next()) {
        Release current_release(query.value("id").toInt(), query.value("version").toInt(),
                                query.value("codename").toString().toStdString(),
                                query.value("isDefault").toBool());
        result.emplace_back(current_release);
    }
    return result;
}

Release Release::get_release_by_id(int id) {
    QSqlQuery query(get_thread_connection());

    query.prepare("SELECT id, version, codename, isDefault FROM release WHERE id = ? LIMIT 1");
    query.bindValue(0, id);
    if (!ci_query_exec(&query)) {
        qDebug() << "Error executing query:" << query.lastError().text();
        return Release();
    }
    if (query.next()) {
        int release_id = query.value(0).toInt();
        int version = query.value(1).toInt();
        QString codename = query.value(2).toString();
        bool isDefault = query.value(3).toBool();

        // Create and return the Release object
        return Release(release_id, version, codename.toStdString(), isDefault);
    } else {
        std::cout << "No release found for ID: " << id << "\n";
    }

    // Return an empty Release object if no match is found
    return Release();
}

bool Release::set_releases(YAML::Node& releases) {
    std::vector<Release> current_releases = get_releases();

    // Use set subtraction to determine which releases need to be added and removed
    // The first operation is releases - current_releases which shows all *additions*
    // The second operation is current_releases - releases which shows all *deletions*
    std::vector<std::string> additions, deletions;

    // Get all of the release codenames from current_releases
    std::set<std::string> current_codenames;
    for (const auto& release : current_releases) {
        current_codenames.insert(release.codename);
    }
    // Convert the YAML node to a proper set
    std::set<std::string> releases_set;
    for (const auto& release : releases) {
        releases_set.insert(release.as<std::string>());
    }

    // Set subtractions
    std::ranges::set_difference(releases_set, current_codenames, std::back_inserter(additions));
    std::ranges::set_difference(current_codenames, releases_set, std::back_inserter(deletions));

    // Insert the additions
    for (const auto& release : additions) {
        auto [version, is_last] = get_version_from_codename(release);
        QSqlQuery query(get_thread_connection());
        query.prepare("INSERT INTO release (version, codename, isDefault) VALUES (?, ?, ?)");
        query.bindValue(0, version);
        query.bindValue(1, QString::fromStdString(release));
        query.bindValue(2, is_last);
        if (!ci_query_exec(&query)) { return false; }
    }

    // Remove the deletions
    for (const auto& release : deletions) {
        QSqlQuery query(get_thread_connection());
        query.prepare("DELETE FROM release WHERE codename = ?");
        query.bindValue(0, QString::fromStdString(release));
        if (!ci_query_exec(&query)) { return false; }
    }

    return true;
}
// End of Release

// Package
//
// We do not define any setter or getter functions here. It is assumed that the Package
// values will be created in batch, in a separate function, likely from the database
Package::Package(int id, const std::string& name, bool large, const std::string& upstream_url, const std::string& packaging_branch, const std::string& packaging_url)
    : id(id), name(name), large(large), upstream_url(upstream_url), packaging_branch(packaging_branch), packaging_url(packaging_url) {
    upstream_browser = transform_url(upstream_url);
    packaging_browser = transform_url(packaging_url);
}

std::vector<Package> Package::get_packages() {
    std::vector<Package> result;
    QString query_str = "SELECT id, name, large, upstream_url, packaging_branch, packaging_url FROM package";
    QSqlQuery query(query_str, get_thread_connection());
    while (query.next()) {
        Package current_package(query.value("id").toInt(), query.value("name").toString().toStdString(),
                                query.value("large").toBool(),
                                query.value("upstream_url").toString().toStdString(),
                                query.value("packaging_branch").toString().toStdString(),
                                query.value("packaging_url").toString().toStdString());
        result.emplace_back(current_package);
    }
    return result;
}

Package Package::get_package_by_id(int id) {
    QSqlQuery query(get_thread_connection());
    query.prepare("SELECT id, name, large, upstream_url, packaging_branch, packaging_url FROM package WHERE id = ? LIMIT 1");
    query.bindValue(0, id);
    if (!ci_query_exec(&query)) {
        qDebug() << "Error executing query:" << query.lastError().text();
        return Package();
    }
    if (query.next()) {
        Package current_package(query.value("id").toInt(), query.value("name").toString().toStdString(),
                                query.value("large").toBool(),
                                query.value("upstream_url").toString().toStdString(),
                                query.value("packaging_branch").toString().toStdString(),
                                query.value("packaging_url").toString().toStdString());
        return current_package;
    }
    return Package();
}

bool Package::set_packages(YAML::Node& packages) {
    std::vector<Package> current_packages = get_packages();
    std::unordered_map<std::string, YAML::Node> packages_map;
    for (const auto& package : packages) {
        if (package["name"]) {
            packages_map[package["name"].as<std::string>()] = YAML::Node(package);
        }
    }

    // Use set subtraction to determine which releases need to be added and removed
    // The first operation is releases - current_releases which shows all *additions*
    // The second operation is current_releases - releases which shows all *deletions*
    std::vector<std::string> additions, deletions;

    // Get all of the release codenames from current_releases
    std::set<std::string> current_pkgs;
    for (const auto& package : current_packages) {
        current_pkgs.insert(package.name);
    }
    // Convert the YAML node to a proper set
    std::set<std::string> packages_set;
    for (const auto& package : packages) {
        packages_set.insert(package["name"].as<std::string>());
    }

    // Set subtractions
    std::ranges::set_difference(packages_set, current_pkgs, std::back_inserter(additions));
    std::ranges::set_difference(current_pkgs, packages_set, std::back_inserter(deletions));

    // Insert the additions
    for (const auto& package : additions) {
        auto package_yaml = packages_map.find(package);
        if (package_yaml == packages_map.end()) { continue; }
        const YAML::Node& package_node = package_yaml->second;

        bool large;
        QString name, upstream_url, packaging_branch, packaging_url;
        name = QString::fromStdString(package);
        large = package_node["large"] ? package_node["large"].as<bool>() : false;
        upstream_url = package_node["upstream_url"] ?
                        QString::fromStdString(package_node["upstream_url"].as<std::string>()) :
                        QString::fromStdString("https://github.com/lxqt/" + name.toStdString() + ".git");
        packaging_url = package_node["packaging_url"] ?
                        QString::fromStdString(package_node["packaging_url"].as<std::string>()) :
                        QString::fromStdString("https://git.lubuntu.me/Lubuntu/" + name.toStdString() + "-packaging.git");
        packaging_branch = package_node["packaging_branch"]
                           ? QString::fromStdString(package_node["packaging_branch"].as<std::string>())
                           : QString("");

        QSqlQuery query(get_thread_connection());
        query.prepare("INSERT INTO package (name, large, upstream_url, packaging_branch, packaging_url) VALUES (?, ?, ?, ?, ?)");
        query.bindValue(0, name);
        query.bindValue(1, large);
        query.bindValue(2, upstream_url);
        query.bindValue(3, packaging_branch);
        query.bindValue(4, packaging_url);
        if (!ci_query_exec(&query)) { return false; }
    }

    // Remove the deletions
    for (const auto& package : deletions) {
        QSqlQuery query(get_thread_connection());
        query.prepare("DELETE FROM package WHERE name = ?");
        query.bindValue(0, QString::fromStdString(package));
        if (!ci_query_exec(&query)) { return false; }
    }

    return true;
}

std::string Package::transform_url(const std::string& url) {
    // Precompiled regex patterns and their replacements
    static const std::vector<std::pair<std::regex, std::string>> patterns = {
        // git.launchpad.net: Append "/commit/?id="
        { std::regex(R"(^(https://git\.launchpad\.net/.*)$)"), "$1/commit/?id=" },

        // code.qt.io: Replace "/qt/" with "/cgit/qt/" and append "/commit/?id="
        { std::regex(R"(^https://code\.qt\.io/qt/([^/]+\.git)$)"), "https://code.qt.io/cgit/qt/$1/commit/?id=" },

        // invent.kde.org: Replace ".git" with "/-/commit/"
        { std::regex(R"(^https://invent\.kde\.org/([^/]+/[^/]+)\.git$)"), "https://invent.kde.org/$1/-/commit/" },

        // git.lubuntu.me: Replace ".git" with "/commit/"
        { std::regex(R"(^https://git\.lubuntu\.me/([^/]+/[^/]+)\.git$)"), "https://git.lubuntu.me/$1/commit/" },

        // gitlab.kitware.com: Replace ".git" with "/-/commit/"
        { std::regex(R"(^https://gitlab\.kitware\.com/([^/]+/[^/]+)\.git$)"), "https://gitlab.kitware.com/$1/-/commit/" },
    };

    // Iterate through patterns and apply the first matching transformation
    for (const auto& [pattern, replacement] : patterns) {
        if (std::regex_match(url, pattern)) {
            return std::regex_replace(url, pattern, replacement);
        }
    }

    // Return the original URL if no patterns match
    return url;
}
// End of Package

// Branch
//
// We do not define any setter or getter functions here. It is assumed that the Branch
// values will be created in batch, in a separate function, likely from the database
Branch::Branch(int id, const std::string& name, const std::string& upload_target, const std::string& upload_target_ssh)
    : id(id), name(name), upload_target(upload_target), upload_target_ssh(upload_target_ssh) {}

std::vector<Branch> Branch::get_branches() {
    std::vector<Branch> result;
    QString query_str = "SELECT id, name, upload_target, upload_target_ssh FROM branch";
    QSqlQuery query(query_str, get_thread_connection());
    while (query.next()) {
        Branch current_branch(query.value("id").toInt(), query.value("name").toString().toStdString(),
                                query.value("upload_target").toString().toStdString(),
                                query.value("upload_target_ssh").toString().toStdString());
        result.emplace_back(current_branch);
    }
    return result;
}

Branch Branch::get_branch_by_id(int id) {
    QSqlQuery query(get_thread_connection());
    query.prepare("SELECT id, name, upload_target, upload_target_ssh FROM branch WHERE id = ? LIMIT 1");
    query.bindValue(0, id);
    if (!ci_query_exec(&query)) {
        qDebug() << "Error executing query:" << query.lastError().text();
        return Branch();
    }
    if (query.next()) {
        Branch current_branch(query.value("id").toInt(), query.value("name").toString().toStdString(),
                              query.value("upload_target").toString().toStdString(),
                              query.value("upload_target_ssh").toString().toStdString());
        return current_branch;
    }
    return Branch();
}
// End of Branch
// PackageConf
//
// This is the main class which will be iterated on by the CI
// It includes pointers to Package, Release, and Branch, plus some basic commit info
PackageConf::PackageConf(int id, std::shared_ptr<Package> package, std::shared_ptr<Release> release, std::shared_ptr<Branch> branch,
                         std::shared_ptr<GitCommit> packaging_commit, std::shared_ptr<GitCommit> upstream_commit)
    : id(id), package(package), release(release), branch(branch), packaging_commit(packaging_commit), upstream_commit(upstream_commit) {}

std::vector<std::shared_ptr<PackageConf>> PackageConf::get_package_confs(std::shared_ptr<std::map<std::string, std::shared_ptr<JobStatus>>> jobstatus_map) {
    Branch _tmp_brch = Branch();
    Package _tmp_pkg = Package();
    Release _tmp_rel = Release();
    std::vector<std::shared_ptr<PackageConf>> result;

    // Get the default release for setting the packaging branch
    std::string default_release;
    for (const Release& release : _tmp_rel.get_releases()) {
        if (release.isDefault) {
            default_release = release.codename;
            break;
        }
    }

    for (const Branch& branch : _tmp_brch.get_branches()) {
        int branch_id = branch.id;
        std::shared_ptr<Branch> shared_branch = std::make_shared<Branch>(branch);

        for (const Release& release : _tmp_rel.get_releases()) {
            int release_id = release.id;
            std::shared_ptr<Release> shared_release = std::make_shared<Release>(release);

            for (const Package& package : _tmp_pkg.get_packages()) {
                int package_id = package.id;

                Package new_package = package;
                if (package.packaging_branch.empty()) {
                    new_package.packaging_branch = "ubuntu/" + default_release;
                }
                std::shared_ptr<Package> shared_package = std::make_shared<Package>(new_package);

                QSqlQuery query_local(get_thread_connection());
                query_local.prepare(R"(
                    SELECT id, upstream_version, ppa_revision, package_id, release_id, branch_id, packaging_commit_id, upstream_commit_id
                    FROM packageconf
                    WHERE package_id = ? AND release_id = ? AND branch_id = ?
                    LIMIT 1)");
                query_local.bindValue(0, package_id);
                query_local.bindValue(1, release_id);
                query_local.bindValue(2, branch_id);
                if (!ci_query_exec(&query_local)) {
                    qDebug() << "Failed to get packageconf:" << query_local.lastError().text()
                             << package_id << release_id << branch_id;
                }

                GitCommit _tmp_commit;

                if (query_local.next()) {
                    QVariant pkg_commit_variant = query_local.value("packaging_commit_id");
                    QVariant ups_commit_variant = query_local.value("upstream_commit_id");

                    std::shared_ptr<GitCommit> packaging_commit_ptr;
                    std::shared_ptr<GitCommit> upstream_commit_ptr;

                    if (!pkg_commit_variant.isNull()) {
                        int pkg_commit_id = pkg_commit_variant.toInt();
                        GitCommit tmp_pkg_commit = _tmp_commit.get_commit_by_id(pkg_commit_id);
                        packaging_commit_ptr = std::make_shared<GitCommit>(tmp_pkg_commit);
                    }

                    if (!ups_commit_variant.isNull()) {
                        int ups_commit_id = ups_commit_variant.toInt();
                        GitCommit tmp_ups_commit = _tmp_commit.get_commit_by_id(ups_commit_id);
                        upstream_commit_ptr = std::make_shared<GitCommit>(tmp_ups_commit);
                    }

                    std::shared_ptr<PackageConf> package_conf = std::make_shared<PackageConf>(
                        query_local.value("id").toInt(),
                        shared_package,
                        shared_release,
                        shared_branch,
                        packaging_commit_ptr,  // can be nullptr if the column was NULL
                        upstream_commit_ptr    // can be nullptr if the column was NULL
                    );
                    package_conf->upstream_version = query_local.value("upstream_version").toString().toStdString();
                    package_conf->ppa_revision = query_local.value("ppa_revision").toInt();

                    result.emplace_back(package_conf);
                }
            }
        }
    }

    {
        // 1. Query all rows from `task`
        QSqlQuery query(get_thread_connection());
        query.prepare(R"(
            SELECT
                t.id AS id,
                pjs.packageconf_id AS packageconf_id,
                t.jobstatus_id AS jobstatus_id,
                t.queue_time AS queue_time,
                t.start_time AS start_time,
                t.finish_time AS finish_time,
                t.successful AS successful,
                t.log AS log
            FROM
                task t
            INNER JOIN
                packageconf_jobstatus_id pjs
            ON
                t.id = pjs.task_id
        )");
        if (!ci_query_exec(&query)) {
            qDebug() << "Failed to load tasks:" << query.lastError().text();
        }

        // 2. For each row in `task`, attach it to the correct PackageConf
        std::map<std::shared_ptr<Package>, std::shared_ptr<Task>> pull_tasks;
        std::map<std::shared_ptr<Package>, std::shared_ptr<Task>> tarball_tasks;
        while (query.next()) {
            int tid = query.value("id").toInt();
            int pcid = query.value("packageconf_id").toInt();
            int jsid = query.value("jobstatus_id").toInt();

            // Find the matching PackageConf in "result"
            auto it = std::find_if(
                result.begin(), result.end(),
                [pcid](const std::shared_ptr<PackageConf>& pc) {
                    return (pc->id == pcid);
                }
            );
            if (it == result.end()) {
                // No matching PackageConf found; skip
                continue;
            }
            std::shared_ptr<PackageConf> pc = *it;

            // Find the matching JobStatus
            std::shared_ptr<JobStatus> jobstatus_ptr;
            for (const auto &kv : *jobstatus_map) {
                if (kv.second && kv.second->id == jsid) {
                    jobstatus_ptr = kv.second;
                    break;
                }
            }
            if (!jobstatus_ptr) {
                // No match for this jobstatus_id, skip
                continue;
            }

            // If the jobstatus matches pull or tarball, grab the existing Task if it exists
            if (jobstatus_ptr->name == "pull") {
                if (auto it = pull_tasks.find(pc->package); it != pull_tasks.end()) {
                    pc->assign_task(jobstatus_ptr, it->second, pc);
                    continue;
                }
            } else if (jobstatus_ptr->name == "tarball") {
                if (auto it = tarball_tasks.find(pc->package); it != tarball_tasks.end()) {
                    pc->assign_task(jobstatus_ptr, it->second, pc);
                    continue;
                }
            }

            // Build a Task
            auto task_ptr = std::make_shared<Task>();
            task_ptr->id = tid;
            task_ptr->jobstatus = jobstatus_ptr;
            task_ptr->queue_time = query.value("queue_time").toLongLong();
            task_ptr->start_time = query.value("start_time").toLongLong();
            task_ptr->finish_time = query.value("finish_time").toLongLong();
            task_ptr->successful = (query.value("successful").toInt() == 1);

            // Attach the log
            task_ptr->log = std::make_shared<Log>();
            task_ptr->log->set_log(query.value("log").toString().toStdString());

            // Point the Task back to its parent
            task_ptr->parent_packageconf = pc;

            // Link the Task to the PackageConf
            pc->assign_task(jobstatus_ptr, task_ptr, pc);

            if (jobstatus_ptr->name == "pull") {
                pull_tasks[pc->package] = task_ptr;
            } else if (jobstatus_ptr->name == "tarball") {
                tarball_tasks[pc->package] = task_ptr;
            }
        }
    }

    return result;
}

std::vector<std::shared_ptr<PackageConf>> PackageConf::get_package_confs_by_package_name(std::vector<std::shared_ptr<PackageConf>> packageconfs, const std::string& package_name) {
    Branch _tmp_brch = Branch();
    Package _tmp_pkg = Package();
    PackageConf _tmp_pkg_conf = PackageConf();
    Release _tmp_rel = Release();
    std::vector<std::shared_ptr<PackageConf>> result;

    // Process the existing packageconf entries; if we find this package, just return that instead
    for (auto pkgconf : packageconfs) {
        if (pkgconf->package->name == package_name) {
            result.emplace_back(pkgconf);
        }
    }
    if (!result.empty()) { return result; }

    // Get the default release for setting the packaging branch
    std::string default_release;
    for (const Release& release : _tmp_rel.get_releases()) {
        if (release.isDefault) {
            default_release = release.codename;
            break;
        }
    }

    for (const Branch& branch : _tmp_brch.get_branches()) {
        int branch_id = branch.id;
        std::shared_ptr<Branch> shared_branch = std::make_shared<Branch>(branch);

        for (const Release& release : _tmp_rel.get_releases()) {
            int release_id = release.id;
            std::shared_ptr<Release> shared_release = std::make_shared<Release>(release);
            for (const Package& package : _tmp_pkg.get_packages()) {
                int package_id = package.id;

                Package new_package = package;
                if (package.packaging_branch.empty()) {
                    new_package.packaging_branch = "ubuntu/" + default_release;
                }
                std::shared_ptr<Package> shared_package = std::make_shared<Package>(new_package);

                QSqlQuery query_local(get_thread_connection());
                query_local.prepare(R"(
                    SELECT id, package_id, release_id, branch_id, packaging_commit_id, upstream_commit_id
                    FROM packageconf
                    WHERE package_id = ? AND release_id = ? AND branch_id = ?
                    LIMIT 1)");
                query_local.bindValue(0, package_id);
                query_local.bindValue(1, release_id);
                query_local.bindValue(2, branch_id);
                if (!ci_query_exec(&query_local)) {
                    qDebug() << "Failed to get packageconf:" << query_local.lastError().text()
                             << package_id << release_id << branch_id;
                }

                GitCommit _tmp_commit;

                if (query_local.next()) {
                    QVariant pkg_commit_variant = query_local.value("packaging_commit_id");
                    QVariant ups_commit_variant = query_local.value("upstream_commit_id");

                    std::shared_ptr<GitCommit> packaging_commit_ptr;
                    std::shared_ptr<GitCommit> upstream_commit_ptr;

                    if (!pkg_commit_variant.isNull()) {
                        int pkg_commit_id = pkg_commit_variant.toInt();
                        GitCommit tmp_pkg_commit = _tmp_commit.get_commit_by_id(pkg_commit_id);
                        packaging_commit_ptr = std::make_shared<GitCommit>(tmp_pkg_commit);
                    }

                    if (!ups_commit_variant.isNull()) {
                        int ups_commit_id = ups_commit_variant.toInt();
                        GitCommit tmp_ups_commit = _tmp_commit.get_commit_by_id(ups_commit_id);
                        upstream_commit_ptr = std::make_shared<GitCommit>(tmp_ups_commit);
                    }

                    std::shared_ptr<PackageConf> package_conf = std::make_shared<PackageConf>(PackageConf(
                        query_local.value("id").toInt(),
                        shared_package,
                        shared_release,
                        shared_branch,
                        packaging_commit_ptr,  // can be nullptr if the column was NULL
                        upstream_commit_ptr    // can be nullptr if the column was NULL
                    ));

                    result.emplace_back(package_conf);
                }
            }
        }
    }

    {
        // 1. Query all rows from `task`
        QSqlQuery query(get_thread_connection());
        query.prepare(R"(
            SELECT id, packageconf_id, jobstatus_id, queue_time, start_time,
                   finish_time, successful, log
            FROM task
        )");
        if (!ci_query_exec(&query)) {
            qDebug() << "Failed to load tasks:" << query.lastError().text();
        }

        // 2. Build a small map of jobstatus_id -> JobStatus object
        //    so we can quickly look up a JobStatus by its ID:
        std::map<int, std::shared_ptr<JobStatus>> all_jobstatuses;
        {
            QSqlQuery q2(get_thread_connection());
            q2.prepare("SELECT id FROM jobstatus");
            if (!ci_query_exec(&q2)) {
                qDebug() << "Failed to load jobstatus list:" << q2.lastError().text();
            }
            while (q2.next()) {
                int js_id = q2.value(0).toInt();
                auto js_ptr = std::make_shared<JobStatus>(JobStatus(js_id));
                all_jobstatuses[js_id] = js_ptr;
            }
        }

        // 3. For each row in `task`, attach it to the correct PackageConf
        while (query.next()) {
            int tid    = query.value("id").toInt();
            int pcid   = query.value("packageconf_id").toInt();
            int jsid   = query.value("jobstatus_id").toInt();

            // Find the matching PackageConf in "result"
            auto it = std::find_if(
                result.begin(), result.end(),
                [pcid](const std::shared_ptr<PackageConf>& pc) {
                    return (pc->id == pcid);
                }
            );
            if (it == result.end()) {
                // No matching PackageConf found; skip
                continue;
            }
            std::shared_ptr<PackageConf> pc = *it;

            // Find the matching JobStatus
            auto jsit = all_jobstatuses.find(jsid);
            if (jsit == all_jobstatuses.end()) {
                // No matching JobStatus found; skip
                continue;
            }
            std::shared_ptr<JobStatus> jobstatus_ptr = jsit->second;

            // Build a Task
            auto task_ptr = std::make_shared<Task>();
            task_ptr->id          = tid;
            task_ptr->jobstatus   = jobstatus_ptr;
            task_ptr->queue_time  = query.value("queue_time").toLongLong();
            task_ptr->start_time  = query.value("start_time").toLongLong();
            task_ptr->finish_time = query.value("finish_time").toLongLong();
            task_ptr->successful  = (query.value("successful").toInt() == 1);

            // Attach the log
            task_ptr->log = std::make_shared<Log>();
            task_ptr->log->set_log(query.value("log").toString().toStdString());

            // Point the Task back to its parent
            task_ptr->parent_packageconf = pc;

            // Finally, link the Task to the PackageConf
            pc->assign_task(jobstatus_ptr, task_ptr, pc);
        }
    }

    return result;
}

int PackageConf::successful_task_count() {
    std::lock_guard<std::mutex> lock(*task_mutex_);

    int successful_count = 0;
    for (const auto& [job_status, task] : jobstatus_task_map_) {
        if (task && task->successful && task->finish_time > 0) {
            ++successful_count;
        }
    }
    return successful_count;
}

int PackageConf::total_task_count() {
    std::lock_guard<std::mutex> lock(*task_mutex_);

    int successful_count = 0;
    for (const auto& [job_status, task] : jobstatus_task_map_) if (task) ++successful_count;
    return successful_count;
}

std::shared_ptr<Task> PackageConf::get_task_by_jobstatus(std::shared_ptr<JobStatus> jobstatus) {
    if (!jobstatus) {
        throw std::invalid_argument("jobstatus is null");
    }

    std::lock_guard<std::mutex> lock(*task_mutex_);

    // Search for the JobStatus in the map
    auto it = jobstatus_task_map_.find(jobstatus);
    if (it != jobstatus_task_map_.end()) {
        return it->second;
    }

    return nullptr;
}

void PackageConf::assign_task(std::shared_ptr<JobStatus> jobstatus, std::shared_ptr<Task> task_ptr, std::weak_ptr<PackageConf> packageconf_ptr) {
    if (!jobstatus || !task_ptr) {
        throw std::invalid_argument("jobstatus or task_ptr is null");
    }

    std::lock_guard<std::mutex> lock(*task_mutex_);
    task_ptr->parent_packageconf = task_ptr->parent_packageconf.lock() ? task_ptr->parent_packageconf : packageconf_ptr;
    jobstatus_task_map_[jobstatus] = task_ptr;
}


bool PackageConf::set_package_confs() {
    // Fetch current PackageConf entries from the database
    QSqlQuery query(get_thread_connection());
    query.prepare("SELECT package_id, release_id, branch_id FROM packageconf");
    if (!ci_query_exec(&query)) {
        qDebug() << "Failed to fetch existing packageconfs:" << query.lastError().text();
        return false;
    }

    std::set<PackageConfPlain> database_confs;
    while (query.next()) {
        PackageConfPlain conf_plain{
            query.value("package_id").toInt(),
            query.value("release_id").toInt(),
            query.value("branch_id").toInt()
        };
        database_confs.insert(conf_plain);
    }

    // Fetch all package, release, and branch IDs
    QSqlQuery pkg_query("SELECT id FROM package", get_thread_connection());
    std::set<int> package_ids;
    while (pkg_query.next()) { package_ids.insert(pkg_query.value(0).toInt()); }

    QSqlQuery rel_query("SELECT id FROM release", get_thread_connection());
    std::set<int> release_ids;
    while (rel_query.next()) { release_ids.insert(rel_query.value(0).toInt()); }

    QSqlQuery br_query("SELECT id FROM branch", get_thread_connection());
    std::set<int> branch_ids;
    while (br_query.next()) { branch_ids.insert(br_query.value(0).toInt()); }


    // Generate desired PackageConf entries (cross-product)
    std::set<PackageConfPlain> desired_confs;
    for (int pkg_id : package_ids) {
        for (int rel_id : release_ids) {
            for (int br_id : branch_ids) {
                desired_confs.insert(PackageConfPlain{pkg_id, rel_id, br_id});
            }
        }
    }

    // Determine additions (desired_confs - database_confs)
    std::vector<PackageConfPlain> additions;
    std::ranges::set_difference(
        desired_confs,
        database_confs,
        std::back_inserter(additions),
        [](auto const &a, auto const &b){ return a < b; });

    // Determine deletions (database_confs - desired_confs)
    std::vector<PackageConfPlain> deletions;
    std::ranges::set_difference(
        database_confs,
        desired_confs,
        std::back_inserter(deletions),
        [](auto const &a, auto const &b){ return a < b; });

    // Insert additions, now including packaging_commit_id/upstream_commit_id as NULL
    for (const auto& conf : additions) {
        QSqlQuery insert_query(get_thread_connection());
        insert_query.prepare(R"(
            INSERT INTO packageconf (
                package_id,
                release_id,
                branch_id,
                packaging_commit_id,
                upstream_commit_id
            ) VALUES (?, ?, ?, NULL, NULL)
        )");
        insert_query.addBindValue(conf.package_id);
        insert_query.addBindValue(conf.release_id);
        insert_query.addBindValue(conf.branch_id);

        if (!ci_query_exec(&insert_query)) {
            log_error("Failed to insert PackageConf: "
                      + insert_query.lastError().text().toStdString()
                      + " Package ID " + std::to_string(conf.package_id)
                      + ", Release ID " + std::to_string(conf.release_id)
                      + ", Branch ID " + std::to_string(conf.branch_id));
            return false;
        }
    }

    // Remove deletions
    for (const auto& conf : deletions) {
        QSqlQuery delete_query(get_thread_connection());
        delete_query.prepare(R"(
            DELETE FROM packageconf
            WHERE package_id = ?
              AND release_id = ?
              AND branch_id = ?
        )");
        delete_query.addBindValue(conf.package_id);
        delete_query.addBindValue(conf.release_id);
        delete_query.addBindValue(conf.branch_id);

        if (!ci_query_exec(&delete_query)) {
            qDebug() << "Failed to delete packageconf:" << delete_query.lastError().text();
            return false;
        }
        log_info("Deleted PackageConf: Package ID " + std::to_string(conf.package_id)
                 + ", Release ID " + std::to_string(conf.release_id)
                 + ", Branch ID " + std::to_string(conf.branch_id));
    }

    return true;
}

void PackageConf::sync() {
    bool oneshot = true;
    while (oneshot) {
        oneshot = false;
        try {
            QSqlQuery query(get_thread_connection());

            if ((!packaging_commit || !upstream_commit) || ((!packaging_commit || packaging_commit->id == 0) && (!upstream_commit || upstream_commit->id == 0))) break;
            else if ((packaging_commit && packaging_commit->id == 0) && (!upstream_commit || upstream_commit->id != 0)) {
                query.prepare("UPDATE packageconf SET upstream_commit_id = ?, upstream_version = ?, ppa_revision = ? WHERE package_id = ? AND branch_id = ? AND release_id = ?");
                query.addBindValue(upstream_commit ? upstream_commit->id : 0);
            }
            else if ((!packaging_commit || (packaging_commit->id != 0)) && (upstream_commit && upstream_commit->id == 0)) {
                query.prepare("UPDATE packageconf SET packaging_commit_id = ?, upstream_version = ?, ppa_revision = ? WHERE package_id = ? AND branch_id = ? AND release_id = ?");
                query.addBindValue(packaging_commit ? packaging_commit->id : 0);
            }
            else {
                query.prepare("UPDATE packageconf SET packaging_commit_id = ?, upstream_commit_id = ?, upstream_version = ?, ppa_revision = ? WHERE package_id = ? AND branch_id = ? AND release_id = ?");
                query.addBindValue(packaging_commit->id);
                query.addBindValue(upstream_commit->id);
            }

            query.addBindValue(QString::fromStdString(upstream_version));
            query.addBindValue(ppa_revision);
            query.addBindValue(package->id);
            query.addBindValue(branch->id);
            query.addBindValue(release->id);

            if (!ci_query_exec(&query)) break;
        } catch (...) {}
    }

    // Also sync all of the child tasks
    {
        std::lock_guard<std::mutex> lock(*task_mutex_);
        for (auto [job_status, task] : jobstatus_task_map_) {
            if (task) {
                auto sync_func = [this, task]() mutable {
                    task->save(id);
                };
                sync_func();
            }
        }
    }
}

bool PackageConf::can_check_source_upload() {
    int _successful_task_count = successful_task_count();
    if (_successful_task_count == 0) return false;

    std::int64_t upload_timestamp = 0;
    std::int64_t source_check_timestamp = 0;
    std::set<std::string> valid_successful_statuses = {"pull", "tarball", "source_build", "upload"};
    for (auto &kv : jobstatus_task_map_) {
        auto &jobstatus = kv.first;
        auto &task_ptr = kv.second;

        if (valid_successful_statuses.contains(jobstatus->name)) _successful_task_count--;

        if (jobstatus->name == "upload" && task_ptr && task_ptr->successful) {
            upload_timestamp = task_ptr->finish_time;
            continue;
        }

        if (jobstatus->name == "source_check" && task_ptr && !task_ptr->successful) {
            source_check_timestamp = task_ptr->finish_time;
            continue;
        }
    }
    bool all_req_tasks_present = _successful_task_count == 0;
    if (!all_req_tasks_present || (upload_timestamp == 0 && source_check_timestamp == 0)) {
        return false;
    } else if (all_req_tasks_present && upload_timestamp != 0 && source_check_timestamp == 0) {
        return true;
    } else if (all_req_tasks_present) {
        return source_check_timestamp <= upload_timestamp;
    }
    return false;
}

bool PackageConf::can_check_builds() {
    std::lock_guard<std::mutex> lock(*task_mutex_);

    if (!(jobstatus_task_map_.size() == 5)) { return false; }

    static const std::array<std::string, 5> statuses = { "pull", "tarball", "source_build", "upload", "source_check" };
    int cur_status = 0;
    std::int64_t cur_timestamp = 0;
    bool return_status = false;
    for (auto &kv : jobstatus_task_map_) {
        auto &jobstatus = kv.first;
        auto &task_ptr = kv.second;

        if (jobstatus->name == statuses[cur_status] && task_ptr) {
            if (task_ptr->finish_time >= cur_timestamp && task_ptr->successful) {
                return_status = true;
                cur_timestamp = task_ptr->finish_time;
                cur_status++;
            } else {
                return_status = false;
                break;
            }
        }
    }
    return return_status && cur_status == 5;
}
// End of PackageConf
// Start of GitCommit
// Constructor which also adds it to the database
GitCommit::GitCommit(
    const std::string& commit_hash,
    const std::string& commit_summary,
    const std::string& commit_message,
    const std::chrono::zoned_time<std::chrono::seconds>& commit_datetime,
    const std::string& commit_author,
    const std::string& commit_committer)
    : commit_hash(commit_hash),
      commit_summary(commit_summary),
      commit_message(commit_message),
      commit_datetime(commit_datetime),
      commit_author(commit_author),
      commit_committer(commit_committer) {
    // Insert the entry into the database right away
    QSqlQuery insert_query(get_thread_connection());

    // Convert commit_datetime to a string in ISO 8601 format
    auto sys_time = commit_datetime.get_sys_time();
    auto time_t = std::chrono::system_clock::to_time_t(sys_time);
    char datetime_buf[20]; // "YYYY-MM-DD HH:MM:SS" -> 19 + 1 for null terminator
    std::strftime(datetime_buf, sizeof(datetime_buf), "%Y-%m-%d %H:%M:%S", std::gmtime(&time_t));

    insert_query.prepare("INSERT INTO git_commit (commit_hash, commit_summary, commit_message, commit_datetime, commit_author, commit_committer) VALUES (?, ?, ?, ?, ?, ?)");
    insert_query.addBindValue(QString::fromStdString(commit_hash));       // Text
    insert_query.addBindValue(QString::fromStdString(commit_summary));   // Text
    insert_query.addBindValue(QString::fromStdString(commit_message));   // Text
    insert_query.addBindValue(QString(datetime_buf));                    // ISO 8601 Text
    insert_query.addBindValue(QString::fromStdString(commit_author));    // Text
    insert_query.addBindValue(QString::fromStdString(commit_committer)); // Text

    if (!ci_query_exec(&insert_query)) {
        // Log error with relevant details
        log_error("Failed to insert GitCommit: " + insert_query.lastError().text().toStdString());
        return;
    }
    QVariant last_id = insert_query.lastInsertId();
    if (last_id.isValid()) {
        id = last_id.toInt();
    }
}

// ID-based constructor
GitCommit::GitCommit(
    const int id,
    const std::string& commit_hash,
    const std::string& commit_summary,
    const std::string& commit_message,
    const std::chrono::zoned_time<std::chrono::seconds>& commit_datetime,
    const std::string& commit_author,
    const std::string& commit_committer)
    : id(id),
      commit_hash(commit_hash),
      commit_summary(commit_summary),
      commit_message(commit_message),
      commit_datetime(commit_datetime),
      commit_author(commit_author),
      commit_committer(commit_committer) {}

std::chrono::zoned_time<std::chrono::seconds> GitCommit::convert_timestr_to_zonedtime(const std::string& datetime_str) {
    std::tm tm_utc{};
    std::sscanf(datetime_str.c_str(), "%d-%d-%d %d:%d:%d",
                &tm_utc.tm_year, &tm_utc.tm_mon, &tm_utc.tm_mday,
                &tm_utc.tm_hour, &tm_utc.tm_min, &tm_utc.tm_sec);
    tm_utc.tm_year -= 1900; // Years since 1900
    tm_utc.tm_mon -= 1;     // Months since January

    // Convert to time_t (UTC)
    std::time_t time_t_value = timegm(&tm_utc);
    auto sys_time = std::chrono::system_clock::from_time_t(time_t_value);

    // Construct zoned_time with std::chrono::seconds
    std::chrono::zoned_time<std::chrono::seconds> db_commit_datetime(
        std::chrono::current_zone(),
        std::chrono::time_point_cast<std::chrono::seconds>(sys_time)
    );

    return db_commit_datetime;
}

GitCommit GitCommit::get_commit_by_id(int id) {
    QSqlQuery query(get_thread_connection());
    query.prepare(
        "SELECT id, commit_hash, commit_summary, commit_message, commit_datetime, "
        "       commit_author, commit_committer "
        "FROM git_commit WHERE id = ? LIMIT 1"
    );
    query.bindValue(0, id);

    if (!ci_query_exec(&query)) {
        qDebug() << "Error executing query:" << query.lastError().text();
        return GitCommit();
    }

    if (query.next()) {
        try {
            int db_id = query.value("id").toInt();
            std::string db_commit_hash = query.value("commit_hash").toString().toStdString();
            std::string db_commit_summary = query.value("commit_summary").toString().toStdString();
            std::string db_commit_message = query.value("commit_message").toString().toStdString();
            std::string db_commit_datetime_str = query.value("commit_datetime").toString().toStdString();
            std::string db_commit_author = query.value("commit_author").toString().toStdString();
            std::string db_commit_committer = query.value("commit_committer").toString().toStdString();

            // Convert datetime string to std::chrono::zoned_time<std::chrono::seconds>
            if (db_commit_datetime_str.size() >= 19) { // "YYYY-MM-DD HH:MM:SS"
                auto db_commit_datetime = convert_timestr_to_zonedtime(db_commit_datetime_str);

                return GitCommit(db_id,
                                 db_commit_hash,
                                 db_commit_summary,
                                 db_commit_message,
                                 db_commit_datetime,
                                 db_commit_author,
                                 db_commit_committer);
            }
        } catch (const std::exception& e) {
            qDebug() << "Error parsing commit_datetime:" << e.what();
        }
    }

    return GitCommit();
}

std::optional<GitCommit> GitCommit::get_commit_by_hash(const std::string commit_hash) {
    QSqlQuery query(get_thread_connection());
    query.prepare(
        "SELECT id, commit_hash, commit_summary, commit_message, commit_datetime, "
        "       commit_author, commit_committer "
        "FROM git_commit WHERE commit_hash = ? LIMIT 1"
    );
    query.bindValue(0, QString::fromStdString(commit_hash));

    if (!ci_query_exec(&query)) {
        qDebug() << "Error executing query:" << query.lastError().text();
        return GitCommit();
    }

    if (query.next()) {
        try {
            int db_id = query.value("id").toInt();
            std::string db_commit_hash = query.value("commit_hash").toString().toStdString();
            std::string db_commit_summary = query.value("commit_summary").toString().toStdString();
            std::string db_commit_message = query.value("commit_message").toString().toStdString();
            std::string db_commit_datetime_str = query.value("commit_datetime").toString().toStdString();
            std::string db_commit_author = query.value("commit_author").toString().toStdString();
            std::string db_commit_committer = query.value("commit_committer").toString().toStdString();

            // Convert datetime string to std::chrono::zoned_time<std::chrono::seconds>
            if (db_commit_datetime_str.size() >= 19) { // "YYYY-MM-DD HH:MM:SS"
                auto db_commit_datetime = convert_timestr_to_zonedtime(db_commit_datetime_str);

                return GitCommit(db_id,
                                 db_commit_hash,
                                 db_commit_summary,
                                 db_commit_message,
                                 db_commit_datetime,
                                 db_commit_author,
                                 db_commit_committer);
            }
        } catch (const std::exception& e) {
            qDebug() << "Error parsing commit_datetime:" << e.what();
        }
    }

    return GitCommit();
}
// End of GitCommit
// Start of JobStatus
JobStatus::JobStatus(int id) : id(id) {
    QSqlQuery query(get_thread_connection());
    query.prepare(
        "SELECT id, build_score, name, display_name "
        "FROM jobstatus WHERE id = ? LIMIT 1"
    );
    query.bindValue(0, id);

    if (!ci_query_exec(&query)) {
        qDebug() << "Error executing query:" << query.lastError().text();
    } else if (query.next()) {
        id = query.value("id").toInt();
        build_score = query.value("build_score").toInt();
        name = query.value("name").toString().toStdString();
        display_name = query.value("display_name").toString().toStdString();
    }
}
// End of JobStatus
// Start of Task
Task::Task(std::shared_ptr<JobStatus> jobstatus, std::int64_t time, std::shared_ptr<PackageConf> packageconf)
    : jobstatus(jobstatus), queue_time(time), is_running(false), log(std::make_shared<Log>()), parent_packageconf(packageconf)
{
    assert(log != nullptr && "Log pointer should never be null");
    QSqlQuery insert_query(get_thread_connection());
    insert_query.prepare("INSERT INTO task (packageconf_id, jobstatus_id, queue_time) VALUES (?, ?, ?)");
    insert_query.addBindValue(packageconf->id);
    insert_query.addBindValue(jobstatus->id);
    insert_query.addBindValue(QVariant::fromValue(static_cast<qlonglong>(time)));

    build_score = jobstatus->build_score;

    if (!ci_query_exec(&insert_query)) {
        // Log error with relevant details
        log_error("Failed to insert Task: " + insert_query.lastError().text().toStdString());
        return;
    }
    QVariant last_id = insert_query.lastInsertId();
    if (last_id.isValid()) {
        id = last_id.toInt();
    }
}
Task::Task() {}


bool Task::compare(const std::shared_ptr<Task>& lhs, const std::shared_ptr<Task>& rhs) {
    if (!lhs && !rhs) return false;
    if (!lhs) return true;  // nullptr is considered less than any valid pointer
    if (!rhs) return false; // Any valid pointer is greater than nullptr
    if (lhs.get() == rhs.get()) return false; // They are considered to be the same

    if (lhs->build_score != rhs->build_score) {
        return lhs->build_score > rhs->build_score; // Higher build_score first
    }
    if (lhs->start_time != rhs->start_time) {
        return lhs->start_time < rhs->start_time; // Earlier start_time first
    }
    if (lhs->finish_time != rhs->finish_time) {
        return lhs->finish_time < rhs->finish_time; // Earlier finish_time first
    }
    if (lhs->queue_time != rhs->queue_time) {
        return lhs->queue_time < rhs->queue_time; // Earlier queue_time first
    }
    if (lhs->get_parent_packageconf()->id != rhs->get_parent_packageconf()->id) {
        return lhs->get_parent_packageconf()->id < rhs->get_parent_packageconf()->id;
    }
    if (lhs->get_parent_packageconf()->release->id != rhs->get_parent_packageconf()->release->id) {
        return lhs->get_parent_packageconf()->release->id < rhs->get_parent_packageconf()->release->id;
    }
    if (lhs->get_parent_packageconf()->package->id != rhs->get_parent_packageconf()->package->id) {
        return lhs->get_parent_packageconf()->package->id < rhs->get_parent_packageconf()->package->id;
    }
    if (lhs->get_parent_packageconf()->branch->id != rhs->get_parent_packageconf()->branch->id) {
        return lhs->get_parent_packageconf()->branch->id < rhs->get_parent_packageconf()->branch->id;
    }
    if (lhs->jobstatus->id != rhs->jobstatus->id) {
        return lhs->jobstatus->id < rhs->jobstatus->id;
    }
    return lhs->id < rhs->id; // Earlier id first
}

std::set<std::shared_ptr<Task>> Task::get_completed_tasks(std::vector<std::shared_ptr<PackageConf>> packageconfs, std::shared_ptr<std::map<std::string, std::shared_ptr<JobStatus>>> job_statuses, int page, int per_page) {
    std::set<std::shared_ptr<Task>> result;

    if (per_page < 1) { per_page = 1; }

    QSqlQuery query(get_thread_connection());
    query.prepare(
        "SELECT id, packageconf_id, jobstatus_id, start_time, finish_time, successful, log "
        "FROM task WHERE start_time != 0 AND finish_time != 0 ORDER BY finish_time DESC LIMIT ? OFFSET ?"
    );
    query.bindValue(0, per_page);
    query.bindValue(1, page);

    if (!ci_query_exec(&query)) {
        qDebug() << "Error getting completed tasks:" << query.lastError().text();
    } while (query.next()) {
        std::shared_ptr<Log> log = std::make_shared<Log>();
        Task this_task;

        this_task.id = query.value("id").toInt();
        for (auto pkgconf : packageconfs) {
            if (pkgconf->id == query.value("packageconf_id").toInt()) {
                this_task.parent_packageconf = pkgconf;
                break;
            }
        }
        for (auto status : *job_statuses) {
            if (status.second->id == query.value("jobstatus_id").toInt()) {
                this_task.jobstatus = status.second;
                break;
            }
        }
        this_task.start_time = static_cast<std::int64_t>(query.value("start_time").toLongLong());
        this_task.finish_time = static_cast<std::int64_t>(query.value("finish_time").toLongLong());
        this_task.successful = query.value("successful").toInt() == 1;
        log->set_log(query.value("log").toString().toStdString());
        this_task.log = log;

        result.insert(std::make_shared<Task>(this_task));
    }

    return result;
}

void Task::save(int _packageconf_id) {
    QSqlQuery query(get_thread_connection());
    query.prepare("UPDATE task SET jobstatus_id = ?, queue_time = ?, start_time = ?, finish_time = ?, successful = ?, log = ? WHERE id = ?");
    query.addBindValue(jobstatus->id);
    query.addBindValue(QVariant::fromValue(static_cast<qlonglong>(queue_time)));
    query.addBindValue(QVariant::fromValue(static_cast<qlonglong>(start_time)));
    query.addBindValue(QVariant::fromValue(static_cast<qlonglong>(finish_time)));
    query.addBindValue(successful);
    query.addBindValue(QString::fromStdString(std::regex_replace(log->get(), std::regex(R"(^\s+)"), "")));
    query.addBindValue(id);
    ci_query_exec(&query);
    QSqlQuery link_query(get_thread_connection());

    int packageconf_id;
    // Max length of int, or default
    if (_packageconf_id == 0 || _packageconf_id == 32767) {
        auto pkgconf = get_parent_packageconf();
        packageconf_id = pkgconf ? pkgconf->id : 0;
    } else {
        packageconf_id = _packageconf_id;
    }

    // Step 1: Update if the record exists
    link_query.prepare(R"(
        UPDATE packageconf_jobstatus_id
        SET task_id = :task_id
        WHERE packageconf_id = :packageconf_id AND jobstatus_id = :jobstatus_id
    )");
    link_query.bindValue(":task_id", id);
    link_query.bindValue(":packageconf_id", packageconf_id);
    link_query.bindValue(":jobstatus_id", jobstatus->id);

    if (!ci_query_exec(&link_query)) {
        qDebug() << "Failed to update packageconf_jobstatus_id for task" << id << ":"
                 << link_query.lastError().text();
        qDebug() << "packageconf_id:" << packageconf_id << "jobstatus_id:" << jobstatus->id
                 << "task_id:" << id;
    } else if (link_query.numRowsAffected() == 0) {
        // Step 2: Insert if no rows were updated
        link_query.prepare(R"(
            INSERT INTO packageconf_jobstatus_id (packageconf_id, jobstatus_id, task_id)
            VALUES (:packageconf_id, :jobstatus_id, :task_id)
        )");
        link_query.bindValue(":packageconf_id", packageconf_id);
        link_query.bindValue(":jobstatus_id", jobstatus->id);
        link_query.bindValue(":task_id", id);

        if (!ci_query_exec(&link_query)) {
            qDebug() << "Failed to insert into packageconf_jobstatus_id for task" << id << ":"
                     << link_query.lastError().text();
            qDebug() << "packageconf_id:" << packageconf_id << "jobstatus_id:" << jobstatus->id
                     << "task_id:" << id;
        }
    }
}
