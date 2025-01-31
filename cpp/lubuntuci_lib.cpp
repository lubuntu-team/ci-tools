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

#include "lubuntuci_lib.h"
#include "ci_logic.h"
#include "common.h"
#include <yaml-cpp/yaml.h>
#include <filesystem>
#include <iostream>
#include <vector>
#include <string>
#include <mutex>
#include <git2.h>

namespace fs = std::filesystem;

/**
 * list_known_repos():
 *   Make sure we call CiLogic::init_global() before reading
 *   the config, otherwise the config node will be empty.
 */
std::vector<std::shared_ptr<PackageConf>> LubuntuCI::list_known_repos(int page, int per_page, const std::string& sort_by, const std::string& sort_order)
{
    cilogic.init_global();
    if (page == 0 || per_page == 0 || sort_by.empty() || sort_order.empty()) { return cilogic.get_config(); }
    return cilogic.get_config("", page, per_page, sort_by, sort_order);
}

/**
 * pull_repo():
 *   - We do not call init_global() here because list_known_repos()
 *     or build_repo() might do it. But calling it again is safe.
 */
bool LubuntuCI::pull_repo(const std::string &repo_name, std::shared_ptr<Log> log)
{
    log->append("Ensuring the global config is initialized...\n");
    cilogic.init_global();
    log->append("Global config is initialized. Getting the configs for the package name...\n");
    auto pkgconfs = cilogic.get_config(repo_name);
    log->append("Configs retrieved. Performing the pull...\n");
    return cilogic.pull_project(pkgconfs.at(0), log);
}

/**
 * create_project_tarball
 */
bool LubuntuCI::create_project_tarball(const std::string &repo_name, std::shared_ptr<Log> log)
{
    cilogic.init_global();
    log->append("Global config is initialized. Getting the configs for the package name...\n");
    auto pkgconfs = cilogic.get_config(repo_name);
    log->append("Configs retrieved. Performing the tarball creation...\n");
    return cilogic.create_project_tarball(pkgconfs.at(0), log);
}

/**
 * build_repo():
 *   - Also safely calls init_global().
 *   - Reads skip_dput from config if present (default = false).
 */
bool LubuntuCI::build_repo(const std::string &repo_name, std::shared_ptr<Log> log)
{
    cilogic.init_global();
    bool success = true;
    for (auto pkgconf : cilogic.get_config(repo_name)) {
        const auto [build_success, changes_files] = cilogic.build_project(pkgconf, log);
        success = success && build_success && cilogic.upload_and_lint(pkgconf, changes_files, false);
    }
    return success;
}
