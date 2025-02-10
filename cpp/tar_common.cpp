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

#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <format>
#include <sstream>
#include <ranges>
#include <sys/stat.h>
#include <unordered_set>

#include "/usr/include/archive.h"
#include <archive_entry.h>
#include "tar_common.h"

namespace fs = std::filesystem;

static const std::string clean_utf8(const char* name) {
    if (!name) return "unknown";
    try {
        std::wstring_convert<std::codecvt_utf8<char32_t>, char32_t> converter;
        converter.from_bytes(name);
        return std::string(name);
    } catch (const std::range_error&) { return "unknown"; }
}

void create_tarball(const std::string &tarball_path,
                    const std::string &directory,
                    const std::vector<std::string> &exclusions,
                    std::shared_ptr<Log> log) {
    if (log) log->append("Creating tarball: " + tarball_path);

    try {
        if (!fs::exists(directory) || !fs::is_directory(directory)) throw std::runtime_error("Source directory does not exist or is not a directory: " + directory);

        struct ArchiveDeleter {
            void operator()(struct archive *a) const {
                if (a) archive_write_free(a);
            }
        };
        std::unique_ptr<struct archive, ArchiveDeleter> a(archive_write_new());
        if (!a) throw std::runtime_error("Failed to create a new archive writer.");

        if (archive_write_add_filter_gzip(a.get()) != ARCHIVE_OK) {
            std::string err = "Failed to add gzip filter: ";
            err += archive_error_string(a.get());
            throw std::runtime_error(err);
        }
        if (archive_write_set_format_pax_restricted(a.get()) != ARCHIVE_OK) {
            std::string err = "Failed to set archive format: ";
            err += archive_error_string(a.get());
            throw std::runtime_error(err);
        }
        if (archive_write_open_filename(a.get(), tarball_path.c_str()) != ARCHIVE_OK) {
            std::string err = "Could not open tarball for writing: ";
            err += archive_error_string(a.get());
            throw std::runtime_error(err);
        }

        // Get the name of the directory we want to include as the top-level folder.
        fs::path base_dir = fs::path(directory).filename();
        std::string base_dir_str = base_dir.string();

        // First add an entry for the top-level directory (with a trailing slash)
        std::string top_dir = base_dir_str + "/";
        {
            struct archive_entry *entry = archive_entry_new();
            if (!entry) throw std::runtime_error("Failed to create archive entry for top-level directory.");
            struct stat file_stat;
            if (stat(base_dir_str.c_str(), &file_stat) == 0) {
                std::string uname = clean_utf8(getpwuid(file_stat.st_uid) ? getpwuid(file_stat.st_uid)->pw_name : "lugito");
                std::string gname = clean_utf8(getgrgid(file_stat.st_gid) ? getgrgid(file_stat.st_gid)->gr_name : "lugito");
                archive_entry_set_uname(entry, uname.c_str());
                archive_entry_set_gname(entry, gname.c_str());
                archive_entry_set_uid(entry, file_stat.st_uid);
                archive_entry_set_gid(entry, file_stat.st_gid);
                archive_entry_set_perm(entry, file_stat.st_mode);
                std::time_t now_time = std::time(nullptr);
                archive_entry_set_mtime(entry, file_stat.st_mtime, 0);
            } else {
                if (log) log->append("Failed to stat: " + top_dir);
                std::time_t now_time = std::time(nullptr);
                archive_entry_set_mtime(entry, now_time, 0);
            }

            archive_entry_set_pathname(entry, top_dir.c_str());
            archive_entry_set_size(entry, 0);
            archive_entry_set_filetype(entry, AE_IFDIR);
            if (archive_write_header(a.get(), entry) != ARCHIVE_OK) {
                std::string err = "Failed to write header for top-level directory: ";
                err += archive_error_string(a.get());
                archive_entry_free(entry);
                throw std::runtime_error(err);
            }
            archive_write_finish_entry(a.get());
            archive_entry_free(entry);
        }

        // Use a set to keep track of directories already added.
        std::unordered_set<std::string> added_directories;

        // Now iterate recursively through the source directory.
        for (auto it = fs::recursive_directory_iterator(directory,
                     fs::directory_options::skip_permission_denied | fs::directory_options::follow_directory_symlink);
             it != fs::recursive_directory_iterator(); ++it) {

            const auto& path = it->path();

            // Skip excluded paths early
            if (std::any_of(exclusions.begin(), exclusions.end(),
                [&path](const std::string& excl) { return path.string().find(excl) != std::string::npos; })) {
                it.disable_recursion_pending();  // Skip further traversal into excluded directories
                continue;
            }

            std::error_code ec;
            const fs::file_status fstatus = it->status(ec);
            if (ec) {
                if (log) log->append("Skipping path due to error: " + path.string() + " (" + ec.message() + ")");
                continue;
            }

            // Ensure we skip any duplicate by checking conflicts between files and directories
            if ((fs::is_directory(fstatus) && fs::exists(path)) ||
                (fs::is_regular_file(fstatus) && fs::is_directory(path))) {
                continue;  // Conflict detected, skip it
            }

            // Generate archive entry
            struct archive_entry* entry = archive_entry_new();
            if (!entry) {
                if (log) log->append("Failed to create archive entry for: " + path.string());
                continue;
            }

            // Set path for the tarball entry (prepend base directory)
            const std::string archive_path = fs::relative(path, directory).string();
            archive_entry_set_pathname(entry, archive_path.c_str());

            // Handle directory/file-specific logic
            if (fs::is_directory(fstatus)) {
                archive_entry_set_filetype(entry, AE_IFDIR);
                archive_entry_set_size(entry, 0);
            } else if (fs::is_regular_file(fstatus)) {
                archive_entry_set_filetype(entry, AE_IFREG);
                archive_entry_set_size(entry, fs::file_size(path, ec));
            } else if (fs::is_symlink(fstatus)) {
                const auto target = fs::read_symlink(path, ec);
                if (!ec) archive_entry_set_symlink(entry, target.c_str());
                archive_entry_set_filetype(entry, AE_IFLNK);
            }

            // Set permissions and ownership
            struct stat file_stat;
            if (stat(path.c_str(), &file_stat) == 0) {
                archive_entry_set_perm(entry, file_stat.st_mode);
                archive_entry_set_uid(entry, file_stat.st_uid);
                archive_entry_set_gid(entry, file_stat.st_gid);
                archive_entry_set_uname(entry, clean_utf8(getpwuid(file_stat.st_uid) ? getpwuid(file_stat.st_uid)->pw_name : "unknown").c_str());
                archive_entry_set_gname(entry, clean_utf8(getgrgid(file_stat.st_gid) ? getgrgid(file_stat.st_gid)->gr_name : "unknown").c_str());
                archive_entry_set_mtime(entry, file_stat.st_mtime, 0);
            }

            // Write the entry to the archive
            if (archive_write_header(a.get(), entry) != ARCHIVE_OK) {
                if (log) log->append("Failed to write header for: " + path.string() + " - " + archive_error_string(a.get()));
                archive_entry_free(entry);
                continue;
            }

            // Handle file content streaming
            if (fs::is_regular_file(fstatus)) {
                std::ifstream in_file(path, std::ios::binary);
                if (in_file) {
                    char buffer[8192];
                    while (in_file.read(buffer, sizeof(buffer)) || in_file.gcount() > 0) {
                        if (archive_write_data(a.get(), buffer, in_file.gcount()) < 0) {
                            if (log) log->append("Failed to write file data: " + path.string());
                            break;
                        }
                    }
                }
            }

            archive_write_finish_entry(a.get());
            archive_entry_free(entry);
        }

        if (archive_write_close(a.get()) != ARCHIVE_OK) {
            std::string err = "Failed to close archive: ";
            err += archive_error_string(a.get());
            throw std::runtime_error(err);
        }
    } catch (const std::exception &e) {
        if (log) log->append("Failed to create tarball: " + tarball_path + "\n" + e.what());
        return;
    }
    if (log) log->append("Tarball created and compressed: " + tarball_path);
}
