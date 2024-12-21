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

#include "common.h"
#include "/usr/include/archive.h"
#include "/usr/include/archive_entry.h"
#include <chrono>
#include <iostream>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <chrono>
#include <regex>

namespace fs = std::filesystem;

static void log_info(const std::string &msg) {
    std::cout << "[INFO] " << msg << "\n";
}
static void log_error(const std::string &msg) {
    std::cerr << "[ERROR] " << msg << "\n";
}

std::string parse_version(const fs::path &changelog_path) {
    if (!fs::exists(changelog_path)) {
        throw std::runtime_error("Changelog not found: " + changelog_path.string());
    }
    std::ifstream f(changelog_path);
    if (!f) throw std::runtime_error("Unable to open changelog");
    std::string first_line;
    std::getline(f, first_line);
    f.close();

    size_t start = first_line.find('(');
    size_t end = first_line.find(')');
    if (start == std::string::npos || end == std::string::npos) {
        throw std::runtime_error("Invalid changelog format");
    }
    std::string version_match = first_line.substr(start+1, end - (start+1));

    std::string epoch;
    std::string upstream_version = version_match;
    if (auto pos = version_match.find(':'); pos != std::string::npos) {
        epoch = version_match.substr(0, pos);
        upstream_version = version_match.substr(pos+1);
    }
    if (auto pos = upstream_version.find('-'); pos != std::string::npos) {
        upstream_version = upstream_version.substr(0, pos);
    }

    std::regex git_regex("(\\+git[0-9]+)?(~[a-z]+)?$");
    upstream_version = std::regex_replace(upstream_version, git_regex, "");

    auto t = std::time(nullptr);
    std::tm tm = *std::gmtime(&t);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y%m%d%H%M", &tm);
    std::string current_date = buf;

    std::string version;
    if (!epoch.empty()) {
        version = epoch + ":" + upstream_version + "+git" + current_date;
    } else {
        version = upstream_version + "+git" + current_date;
    }

    return version;
}

void run_command(const std::vector<std::string> &cmd, const std::optional<fs::path> &cwd, bool show_output) {
    std::string full_cmd;
    for (const auto &c : cmd) {
        full_cmd += c + " ";
    }
    if (cwd) {
        full_cmd = "cd " + cwd->string() + " && " + full_cmd;
    }
    log_info("Executing: " + full_cmd);
    int ret = std::system(full_cmd.c_str());
    if (ret != 0) {
        log_error("Command failed: " + full_cmd);
        throw std::runtime_error("Command failed");
    }
    if (show_output) {
        std::cout << "[INFO] Command succeeded: " + full_cmd << "\n";
    }
}

void clean_old_logs(const fs::path &log_dir, int max_age_seconds) {
    auto now = std::chrono::system_clock::now();
    for (auto &entry : fs::directory_iterator(log_dir)) {
        if (fs::is_regular_file(entry)) {
            auto ftime = fs::last_write_time(entry);
            auto sctp = decltype(ftime)::clock::to_sys(ftime);
            auto age = std::chrono::duration_cast<std::chrono::seconds>(now - sctp).count();
            if (age > max_age_seconds) {
                fs::remove(entry);
            }
        }
    }
}


void create_tarball(const std::string& tarballPath, const std::string& directory, const std::vector<std::string>& exclusions) {
    std::cout << "[INFO] Creating tarball: " << tarballPath << std::endl;

    struct archive* a = archive_write_new();
    if (!a) {
        throw std::runtime_error("Failed to create a new archive.");
    }

    if (archive_write_add_filter_gzip(a) != ARCHIVE_OK) {
        std::string err = "Failed to add gzip filter: ";
        err += archive_error_string(a);
        archive_write_free(a);
        throw std::runtime_error(err);
    }

    if (archive_write_set_format_pax_restricted(a) != ARCHIVE_OK) {
        std::string err = "Failed to set format: ";
        err += archive_error_string(a);
        archive_write_free(a);
        throw std::runtime_error(err);
    }

    if (archive_write_open_filename(a, tarballPath.c_str()) != ARCHIVE_OK) {
        std::string err = "Could not open tarball for writing: ";
        err += archive_error_string(a);
        archive_write_free(a);
        throw std::runtime_error(err);
    }

    for (auto it = fs::recursive_directory_iterator(directory, fs::directory_options::follow_directory_symlink | fs::directory_options::skip_permission_denied);
         it != fs::recursive_directory_iterator(); ++it) {
        const auto& path = it->path();
        std::error_code ec;

        fs::path relativePath = fs::relative(path, directory, ec);
        if (ec) {
            log_error("Failed to compute relative path for: " + path.string() + " Error: " + ec.message());
            continue;
        }

        bool excluded = std::any_of(exclusions.begin(), exclusions.end(), [&relativePath](const std::string& exclusion) {
            return relativePath.string().find(exclusion) != std::string::npos;
        });
        if (excluded) { continue; }

        fs::file_status fstatus = it->symlink_status(ec);
        if (ec) {
            log_error("Failed to get file status for: " + path.string() + " Error: " + ec.message());
            continue;
        }

        struct archive_entry* entry = archive_entry_new();
        if (!entry) {
            log_error("Failed to create archive entry for: " + path.string());
            archive_write_free(a);
            throw std::runtime_error("Failed to create archive entry.");
        }

        archive_entry_set_pathname(entry, relativePath.c_str());

        // Set file type, permissions, and size
        if (fs::is_regular_file(fstatus)) {
            // Regular file
            uintmax_t filesize = fs::file_size(path, ec);
            if (ec) {
                log_error("Cannot get file size for: " + path.string() + " Error: " + ec.message());
                archive_entry_free(entry);
                continue;
            }
            archive_entry_set_size(entry, static_cast<off_t>(filesize));
            archive_entry_set_filetype(entry, AE_IFREG);
            archive_entry_set_perm(entry, static_cast<mode_t>(fstatus.permissions()));
        }
        else if (fs::is_symlink(fstatus)) {
            fs::path target = fs::read_symlink(path, ec);
            if (ec) {
                log_error("Cannot read symlink for: " + path.string() + " Error: " + ec.message());
                archive_entry_free(entry);
                continue;
            }
            archive_entry_set_symlink(entry, target.c_str());
            archive_entry_set_filetype(entry, AE_IFLNK);
            archive_entry_set_perm(entry, static_cast<mode_t>(fstatus.permissions()));
        }
        else if (fs::is_directory(fstatus)) {
            archive_entry_set_size(entry, 0);
            archive_entry_set_filetype(entry, AE_IFDIR);
            archive_entry_set_perm(entry, static_cast<mode_t>(fstatus.permissions()));
        }
        else {
            log_error("Unsupported file type for: " + path.string());
            archive_entry_free(entry);
            continue;
        }

        // Retrieve and set the modification time
        fs::file_time_type ftime = fs::last_write_time(path, ec);
        std::time_t mtime;
        if (ec) {
            log_error("Failed to get last write time for: " + path.string() + " Error: " + ec.message());
            // Obtain current UTC time as fallback
            auto now = std::chrono::system_clock::now();
            mtime = std::chrono::system_clock::to_time_t(now);
            log_info("Setting default mtime (current UTC time) for: " + path.string());
        } else {
            mtime = to_time_t(ftime);
        }
        archive_entry_set_mtime(entry, mtime, 0);

        if (archive_write_header(a, entry) != ARCHIVE_OK) {
            log_error("Failed to write header for: " + path.string() + " Error: " + archive_error_string(a));
            archive_entry_free(entry);
            continue;
        }

        if (fs::is_regular_file(fstatus)) {
            std::ifstream fileStream(path, std::ios::binary);
            if (!fileStream) {
                log_error("Failed to open file for reading: " + path.string());
                archive_entry_free(entry);
                continue;
            }

            const std::size_t bufferSize = 8192;
            char buffer[bufferSize];
            while (fileStream) {
                fileStream.read(buffer, bufferSize);
                std::streamsize bytesRead = fileStream.gcount();
                if (bytesRead > 0) {
                    if (archive_write_data(a, buffer, static_cast<size_t>(bytesRead)) < 0) {
                        log_error("Failed to write data for: " + path.string() + " Error: " + archive_error_string(a));
                        break;
                    }
                }
            }

            if (fileStream.bad()) {
                log_error("Error reading file: " + path.string());
            }
        }

        archive_entry_free(entry);
    }

    if (archive_write_close(a) != ARCHIVE_OK) {
        std::string err = "Failed to close archive: ";
        err += archive_error_string(a);
        archive_write_free(a);
        throw std::runtime_error(err);
    }

    if (archive_write_free(a) != ARCHIVE_OK) {
        std::string err = "Failed to free archive: ";
        err += archive_error_string(a);
        throw std::runtime_error(err);
    }

    std::cout << "[INFO] Tarball created and compressed: " << tarballPath << std::endl;
}

std::string get_current_utc_time() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::tm tm_utc;
    gmtime_r(&now_time, &tm_utc);
    char buf[20];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_utc);
    return std::string(buf);
}

std::time_t to_time_t(const fs::file_time_type& ftime) {
    using namespace std::chrono;
    // Convert to system_clock time_point
    auto sctp = time_point_cast<system_clock::duration>(ftime - fs::file_time_type::clock::now()
        + system_clock::now());
    return system_clock::to_time_t(sctp);
}
