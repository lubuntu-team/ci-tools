#pragma once
#include <string>
#include <vector>
#include <filesystem>
#include <optional>

std::string parse_version(const std::filesystem::path &changelog_path);
void run_command(const std::vector<std::string> &cmd, const std::optional<std::filesystem::path> &cwd = std::nullopt, bool show_output=false);
void clean_old_logs(const std::filesystem::path &log_dir, int max_age_seconds=86400);
void create_tarball(const std::string &name, const std::filesystem::path &source_dir, const std::vector<std::string> &exclusions);
