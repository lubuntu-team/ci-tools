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

#pragma once
#include <string>
#include <vector>
#include <filesystem>
#include <optional>

std::string parse_version(const std::filesystem::path &changelog_path);
void run_command(const std::vector<std::string> &cmd, const std::optional<std::filesystem::path> &cwd = std::nullopt, bool show_output=false);
void clean_old_logs(const std::filesystem::path &log_dir, int max_age_seconds=86400);
void create_tarball(const std::string &name, const std::filesystem::path &source_dir, const std::vector<std::string> &exclusions);