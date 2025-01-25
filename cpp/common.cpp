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

#include "common.h"
#include "utilities.h"
#include "/usr/include/archive.h"
#include <archive_entry.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cstdio>
#include <cstdlib>
#include <regex>
#include <chrono>
#include <ctime>
#include <mutex>
#include <unordered_set>
#include <QProcess>

// Define the global 'verbose' variable
bool verbose = false;

// Logger function implementations
void log_info(const std::string &msg) {
    std::cout << "[INFO] " << msg << "\n";
}

void log_warning(const std::string &msg) {
    std::cerr << "[WARNING] " << msg << "\n";
}

void log_error(const std::string &msg) {
    std::cerr << "[ERROR] " << msg << "\n";
}

void log_verbose(const std::string &msg) {
    if (verbose) {
        std::cout << "[VERBOSE] " << msg << "\n";
    }
}

namespace fs = std::filesystem;

bool run_command(const std::vector<std::string> &cmd,
                 const std::optional<std::filesystem::path> &cwd,
                 bool show_output,
                 std::shared_ptr<Log> log) {
    if (cmd.empty()) {
        throw std::runtime_error("Command is empty");
    }

    QProcess process;

    // Set the working directory if provided
    if (cwd) {
        process.setWorkingDirectory(QString::fromStdString(cwd->string()));
    }

    // Set up the environment (if needed)
    QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
    process.setProcessEnvironment(env);

    // Extract executable and arguments
    QString program = QString::fromStdString(cmd[0]);
    QStringList arguments;
    for (size_t i = 1; i < cmd.size(); ++i) {
        arguments << QString::fromStdString(cmd[i]);
    }

    // Start the command
    process.start(program, arguments);
    if (!process.waitForStarted()) {
        throw std::runtime_error("Failed to start the command: " + program.toStdString());
    }

    // Stream output while the process is running
    while (process.state() == QProcess::Running) {
        if (process.waitForReadyRead()) {
            QByteArray output = process.readAllStandardOutput();
            QByteArray error = process.readAllStandardError();

            if (log) {
                log->append(output.toStdString());
                log->append(error.toStdString());
            }

            if (show_output) {
                std::cout << output.toStdString();
                std::cerr << error.toStdString();
            }
        }
    }

    // Wait for the process to finish
    process.waitForFinished();

    // Capture return code and errors
    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        QByteArray error_output = process.readAllStandardError();
        std::string error_message = "Command failed with exit code: " + std::to_string(process.exitCode());
        if (!error_output.isEmpty()) {
            error_message += "\nError Output: " + error_output.toStdString();
        }
        throw std::runtime_error(error_message);
    }

    return true;
}

// Function to extract excluded files from a copyright file
std::vector<std::string> extract_files_excluded(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + filepath);
    }

    std::vector<std::string> files_excluded;
    std::string line;
    std::regex files_excluded_pattern(R"(Files-Excluded:\s*(.*))");
    bool in_files_excluded = false;

    while (std::getline(file, line)) {
        if (std::regex_match(line, files_excluded_pattern)) {
            in_files_excluded = true;
            std::smatch match;
            if (std::regex_search(line, match, files_excluded_pattern) && match.size() > 1) {
                files_excluded.emplace_back(match[1]);
            }
        } else if (in_files_excluded) {
            if (!line.empty() && (line[0] == ' ' || line[0] == '\t')) {
                files_excluded.emplace_back(line.substr(1));
            } else {
                break; // End of Files-Excluded block
            }
        }
    }

    return files_excluded;
}

// Function to create a tarball
void create_tarball(const std::string& tarballPath, const std::string& directory, const std::vector<std::string>& exclusions, std::shared_ptr<Log> log) {
    log->append("Creating tarball: " + tarballPath);

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

    // Initialize a set to track added relative paths to prevent duplication
    std::unordered_set<std::string> added_paths;

    // Iterate through the directory recursively without following symlinks
    for (auto it = fs::recursive_directory_iterator(
             directory,
             fs::directory_options::skip_permission_denied);
         it != fs::recursive_directory_iterator(); ++it) {
        const auto& path = it->path();
        std::error_code ec;

        fs::path relative_path = fs::relative(path, directory, ec);
        if (ec) {
            log->append("Failed to compute relative path for: " + path.string() + " Error: " + ec.message());
            continue;
        }

        // Normalize the relative path to avoid discrepancies
        fs::path normalized_relative_path = relative_path.lexically_normal();
        std::string relative_path_str = normalized_relative_path.string();

        // Check if this path has already been added
        if (!added_paths.insert(relative_path_str).second) {
            log->append("Duplicate path detected and skipped: " + relative_path_str);
            continue; // Skip adding this duplicate path
        }

        // Exclusion logic (if any exclusions are provided)
        bool excluded = std::any_of(exclusions.begin(), exclusions.end(), [&relative_path_str](const std::string& exclusion) {
            return relative_path_str.find(exclusion) != std::string::npos;
        });
        if (excluded) { continue; }

        fs::file_status fstatus = it->symlink_status(ec);
        if (ec) {
            log->append("Failed to get file status for: " + path.string() + " Error: " + ec.message());
            continue;
        }

        struct archive_entry* entry = archive_entry_new();
        if (!entry) {
            log->append("Failed to create archive entry for: " + path.string());
            archive_write_free(a);
            throw std::runtime_error("Failed to create archive entry.");
        }

        std::string entry_path = relative_path_str;
        if (fs::is_directory(fstatus)) {
            // Ensure the directory pathname ends with '/'
            if (!entry_path.empty() && entry_path.back() != '/') {
                entry_path += '/';
            }
            archive_entry_set_pathname(entry, entry_path.c_str());
        } else {
            archive_entry_set_pathname(entry, entry_path.c_str());
        }

        // Set file type, permissions, and size
        if (fs::is_regular_file(fstatus)) {
            // Regular file
            uintmax_t filesize = fs::file_size(path, ec);
            if (ec) {
                log->append("Cannot get file size for: " + path.string() + " Error: " + ec.message());
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
                log->append("Cannot read symlink for: " + path.string() + " Error: " + ec.message());
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
            log->append("Unsupported file type for: " + path.string());
            archive_entry_free(entry);
            continue;
        }

        // Retrieve and set the modification time
        fs::file_time_type ftime = fs::last_write_time(path, ec);
        std::time_t mtime;
        if (ec) {
            log->append("Failed to get last write time for: " + path.string() + " Error: " + ec.message());
            // Obtain current UTC time as fallback
            auto now = std::chrono::system_clock::now();
            mtime = std::chrono::system_clock::to_time_t(now);
            log->append("Setting default mtime (current UTC time) for: " + path.string());
        } else {
            mtime = to_time_t(ftime);
        }
        archive_entry_set_mtime(entry, mtime, 0);

        if (archive_write_header(a, entry) != ARCHIVE_OK) {
            log->append("Failed to write header for: " + path.string() + " Error: " + archive_error_string(a));
            archive_entry_free(entry);
            continue;
        }

        if (fs::is_regular_file(fstatus)) {
            std::ifstream fileStream(path, std::ios::binary);
            if (!fileStream) {
                log->append("Failed to open file for reading: " + path.string());
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
                        log->append("Failed to write data for: " + path.string() + " Error: " + archive_error_string(a));
                        break;
                    }
                }
            }

            if (fileStream.bad()) {
                log->append("Error reading file: " + path.string());
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

    log->append("Tarball created and compressed: " + tarballPath);
}
