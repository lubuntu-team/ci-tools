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

#ifndef GIT_COMMON_H
#define GIT_COMMON_H

#include "ci_database_objs.h"
#include <git2.h>

namespace fs = std::filesystem;

void ensure_git_inited();
GitCommit get_commit_from_pkg_repo(const std::string& repo_name,
                                   std::shared_ptr<Log> log);
void clone_or_fetch(const fs::path &repo_dir,
                    const std::string &repo_url,
                    const std::optional<std::string> &branch,
                    std::shared_ptr<Log> log = NULL);
void reset_changelog(const fs::path &repo_dir,
                     const fs::path &changelog_path);

#endif // GIT_COMMON_H
