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

#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <format>
#include <regex>
#include <sstream>
#include <random>
#include <ranges>
#include <sys/stat.h>
#include <unordered_set>

#include "utilities.h"

#include "/usr/include/archive.h"
#include <archive_entry.h>
#include <zlib.h>
#include <curl/curl.h>

bool verbose = false;

// Define a semaphore with a maximum of 10 concurrent jobs
static std::counting_semaphore<10> sem(10);

// Job queue and synchronization primitives
static std::mutex queue_mutex;
static std::atomic<bool> daemon_running{false};

// Function to read the entire content of a file into a string
std::string read_file(const fs::path& file_path) {
    std::ifstream in_file(file_path, std::ios::binary);
    if (in_file) {
        return std::string((std::istreambuf_iterator<char>(in_file)),
                           std::istreambuf_iterator<char>());
    }
    return "";
}

// Function to write a string into a file
void write_file(const fs::path& file_path, const std::string& content) {
    std::ofstream out_file(file_path, std::ios::binary);
    if (out_file) {
        out_file << content;
    }
}

// Function to perform in-place regex replace on a file
void regex_replace_in_file(const fs::path& file_path,
                           const std::string& pattern,
                           const std::string& replacement) {
    std::string content = read_file(file_path);
    content = std::regex_replace(content, std::regex(pattern), replacement);
    write_file(file_path, content);
}

// Function to decompress gzipped files
std::string decompress_gzip(const fs::path& file_path) {
    gzFile infile = gzopen(file_path.c_str(), "rb");
    if (!infile) return "";

    std::string decompressed_data;
    char buffer[8192];
    int num_read = 0;
    while ((num_read = gzread(infile, buffer, sizeof(buffer))) > 0) {
        decompressed_data.append(buffer, num_read);
    }
    gzclose(infile);
    return decompressed_data;
}

// Helper function for libcurl write callback
size_t write_data(void* ptr, size_t size, size_t nmemb, void* stream) {
    FILE* out = static_cast<FILE*>(stream);
    return fwrite(ptr, size, nmemb, out);
}

// Function to download a file with timestamping using libcurl
void download_file_with_timestamping(const std::string& url,
                                     const fs::path& output_path,
                                     const fs::path& log_file_path,
                                     std::mutex& log_mutex) {
    CURL* curl;
    CURLcode res;
    FILE* fp;
    curl = curl_easy_init();
    if (curl) {
        fs::path temp_file_path = output_path.string() + ".tmp";
        fp = fopen(temp_file_path.c_str(), "wb");

        if (!fp) {
            std::cerr << "Failed to open file: " << temp_file_path << std::endl;
            curl_easy_cleanup(curl);
            return;
        }

        // Set curl options for downloading the file
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

        // Timestamping: set If-Modified-Since header
        struct stat file_info;
        if (stat(output_path.c_str(), &file_info) == 0) {
            // Set the time condition to If-Modified-Since
            curl_easy_setopt(curl, CURLOPT_TIMECONDITION, CURL_TIMECOND_IFMODSINCE);
            curl_easy_setopt(curl, CURLOPT_TIMEVALUE, file_info.st_mtime);
        }

        // Perform the file download
        res = curl_easy_perform(curl);

        // Get the HTTP response code
        long response_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

        fclose(fp);
        curl_easy_cleanup(curl);

        // Log the result and handle the downloaded file
        {
            std::lock_guard<std::mutex> lock(log_mutex);
            std::ofstream log_file(log_file_path, std::ios::app);
            if (res == CURLE_OK && (response_code == 200 || response_code == 201)) {
                fs::rename(temp_file_path, output_path);
                log_file << "Downloaded: " << url << std::endl;
            } else if (response_code == 304) {
                fs::remove(temp_file_path);
                log_file << "Not Modified: " << url << std::endl;
            } else {
                fs::remove(temp_file_path);
                log_file << "Failed to download: " << url << std::endl;
            }
        }
    } else {
        std::cerr << "Failed to initialize CURL." << std::endl;
    }
}

std::filesystem::path create_temp_directory() {
    auto temp_dir = std::filesystem::temp_directory_path() / generate_random_string(32);
    std::filesystem::create_directory(temp_dir);
    return temp_dir;
}

// Function to copy a directory recursively
void copy_directory(const fs::path& source, const fs::path& destination) {
    if (!std::filesystem::exists(source) || !std::filesystem::is_directory(source)) {
        throw std::runtime_error("Source directory does not exist or is not a directory: " + source.string());
    }

    // Create the destination directory
    std::filesystem::create_directories(destination);

    // Copy files and directories recursively
    for (const auto& entry : std::filesystem::recursive_directory_iterator(source)) {
        auto relative_path = std::filesystem::relative(entry.path(), source);
        auto target_path = destination / relative_path;

        try {
            if (std::filesystem::is_directory(entry)) {
                std::filesystem::create_directory(target_path);
            } else if (std::filesystem::is_regular_file(entry)) {
                std::filesystem::copy(entry, target_path, std::filesystem::copy_options::overwrite_existing);
            }
        } catch (...) {
            continue;
        }
    }
}

// Function to generate a random string of given length
std::string generate_random_string(size_t length) {
    const std::string chars =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";
    thread_local std::mt19937 rg{std::random_device{}()};
    thread_local std::uniform_int_distribution<> pick(0, chars.size() - 1);
    std::string s;
    s.reserve(length);
    while (length--)
        s += chars[pick(rg)];
    return s;
}

// Function to get current UTC time formatted as per the given format string
std::string get_current_utc_time(const std::string& format) {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::tm tm_utc;
    gmtime_r(&now_time, &tm_utc);
    char buf[64]; // Ensure sufficient buffer size for different formats
    std::strftime(buf, sizeof(buf), format.c_str(), &tm_utc);
    return std::string(buf);
}

std::vector<std::string> split_string(const std::string& input, const std::string& delimiter) {
    std::vector<std::string> result;
    size_t start = 0;
    size_t end = 0;

    while ((end = input.find(delimiter, start)) != std::string::npos) {
        result.emplace_back(input.substr(start, end - start));
        start = end + delimiter.length();
    }

    // Add the remaining part of the string
    result.emplace_back(input.substr(start));
    return result;
}

std::string remove_suffix(const std::string& input, const std::string& suffix) {
    if (input.size() >= suffix.size() &&
        input.compare(input.size() - suffix.size(), suffix.size(), suffix) == 0) {
        return input.substr(0, input.size() - suffix.size());
    }
    return input; // Return the original string if the suffix doesn't exist
}

// Utility which basically does the following:
// "noble" (std::string) -> 2504 (int)
// The bool represents whether this codename is the development release
std::pair<int, bool> get_version_from_codename(const std::string& codename) {
    std::ifstream file("/usr/share/distro-info/ubuntu.csv");
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file.");
    }

    std::string line;
    // Skip the header line
    std::getline(file, line);

    std::string last_codename;
    int version = 0;

    while (std::getline(file, line)) {
        std::istringstream iss(line);
        std::string version_str, name, series;
        std::getline(iss, version_str, ',');
        std::getline(iss, name, ',');
        std::getline(iss, series, ',');

        if (series == codename) {
            version_str.erase(std::remove(version_str.begin(), version_str.end(), '.'),
                              version_str.end());
            version = std::stoi(version_str);
        }
        last_codename = series;
    }

    bool is_last = (codename == last_codename);

    if (version == 0) {
        throw std::runtime_error("Codename not found.");
    }

    return {version, is_last};
}

void run_task_every(std::stop_token _stop_token, int interval_minutes, std::function<void()> task) {
    if (interval_minutes < 2) interval_minutes = 2;
    std::this_thread::sleep_for(std::chrono::minutes(interval_minutes / 2));

    while (!_stop_token.stop_requested()) {
        task();
        std::this_thread::sleep_for(std::chrono::minutes(interval_minutes));
    }
}

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

static const std::string clean_utf8(const char* name) {
    if (!name) return "unknown";
    try {
        std::wstring_convert<std::codecvt_utf8<char32_t>, char32_t> converter;
        converter.from_bytes(name);
        return std::string(name);
    } catch (const std::range_error&) return "unknown";
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
        {
            struct archive_entry *entry = archive_entry_new();
            if (!entry) throw std::runtime_error("Failed to create archive entry for top-level directory.");
            std::string top_dir = base_dir_str + "/";
            struct stat file_stat;
            if (stat(top_dir.c_str(), &file_stat) == 0) {
                std::string uname = clean_utf8(getpwuid(file_stat.st_uid) ? getpwuid(file_stat.st_uid)->pw_name : "lugito");
                std::string gname = clean_utf8(getgrgid(file_stat.st_gid) ? getgrgid(file_stat.st_gid)->gr_name : "lugito");
                archive_entry_set_uname(entry, uname);
                archive_entry_set_gname(entry, gname);
                archive_entry_set_uid(entry, file_stat.st_uid);
                archive_entry_set_gid(entry, file_stat.st_gid);
                archive_entry_set_perm(entry, file_stat.st_mode);
            } else {
                if (log) log->append("Failed to stat: " + top_dir);
            }

            archive_entry_set_pathname(entry, top_dir.c_str());
            archive_entry_set_size(entry, 0);
            archive_entry_set_filetype(entry, AE_IFDIR);
            std::time_t now_time = std::time(nullptr);
            archive_entry_set_mtime(entry, now_time, 0);
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
        for (auto it = fs::recursive_directory_iterator(directory, fs::directory_options::skip_permission_denied);
             it != fs::recursive_directory_iterator(); ++it) {
            const auto &path = it->path();
            std::error_code ec;
            fs::path rel_path = fs::relative(path, directory, ec);
            if (ec) {
                if (log) log->append(std::format("Failed to compute relative path for: {} Error: {}", path.string(), ec.message()));
                continue;
            }

            // Prepend the base directory name so that the entry becomes "base_dir/..."
            fs::path entry_path = fs::path(base_dir_str) / rel_path;
            std::string entry_path_str = entry_path.string();

            // Skip any paths that match one of the exclusions
            bool is_excluded = std::any_of(exclusions.begin(), exclusions.end(),
                                           [&entry_path_str](const std::string &excl) {
                                               return entry_path_str.find(excl) != std::string::npos;
                                           });
            if (is_excluded) continue;

            fs::file_status fstatus = it->symlink_status(ec);
            if (ec) {
                if (log) log->append(std::format("Failed to get file status for: {} Error: {}", path.string(), ec.message()));
                continue;
            }

            // For non-symlink directories, check if we already added it (using canonical path)
            if (fs::is_directory(fstatus) && !fs::is_symlink(fstatus)) {
                fs::path canon = fs::canonical(path, ec);
                if (ec) canon = rel_path;
                std::string canon_str = canon.string();
                if (added_directories.find(canon_str) != added_directories.end()) continue;
                added_directories.insert(canon_str);
            }

            // Create a new archive entry for this file/directory/symlink.
            struct archive_entry *entry = archive_entry_new();
            if (!entry) {
                if (log) log->append(std::format("Failed to create archive entry for: {}", path.string()));
                continue;
            }

            struct stat file_stat;
            if (stat(path.c_str(), &file_stat) == 0) {
                std::string uname = clean_utf8(getpwuid(file_stat.st_uid) ? getpwuid(file_stat.st_uid)->pw_name : "lugito");
                std::string gname = clean_utf8(getgrgid(file_stat.st_gid) ? getgrgid(file_stat.st_gid)->gr_name : "lugito");
                archive_entry_set_uname(entry, uname);
                archive_entry_set_gname(entry, gname);
                archive_entry_set_uid(entry, file_stat.st_uid);
                archive_entry_set_gid(entry, file_stat.st_gid);
                archive_entry_set_perm(entry, file_stat.st_mode);
                archive_entry_set_size(entry, fs::is_regular_file(path) ? file_stat.st_size : 0);
            } else {
                if (log) log->append("Failed to stat: " + path.string());
            }

            // Make sure directories end with a '/'
            if (fs::is_directory(fstatus)) {
                if (!entry_path_str.empty() && entry_path_str.back() != '/') entry_path_str.push_back('/');
            }
            archive_entry_set_pathname(entry, entry_path_str.c_str());

            if (fs::is_regular_file(fstatus)) {
                uintmax_t filesize = fs::file_size(path, ec);
                if (ec) {
                    if (log) log->append(std::format("Cannot get file size for: {} Error: {}", path.string(), ec.message()));
                    archive_entry_free(entry);
                    continue;
                }
                archive_entry_set_filetype(entry, AE_IFREG);
            } else if (fs::is_directory(fstatus)) {
                archive_entry_set_filetype(entry, AE_IFDIR);
            } else if (fs::is_symlink(fstatus)) {
                fs::path target = fs::read_symlink(path, ec);
                if (ec) {
                    if (log) log->append(std::format("Cannot read symlink for: {} Error: {}", path.string(), ec.message()));
                    archive_entry_free(entry);
                    continue;
                }
                archive_entry_set_symlink(entry, target.c_str());
                archive_entry_set_filetype(entry, AE_IFLNK);
            } else {
                if (log) log->append(std::format("Unsupported file type for: {}", path.string()));
                archive_entry_free(entry);
                continue;
            }

            // Set the modification time
            fs::file_time_type ftime = fs::last_write_time(path, ec);
            std::time_t mtime;
            if (ec) {
                if (log) log->append(std::format("Failed to get last write time for: {} Error: {}", path.string(), ec.message()));
                mtime = std::time(nullptr);
                if (log) log->append(std::format("Setting current UTC time as modification time for: {}", path.string()));
            } else mtime = std::chrono::system_clock::to_time_t(std::chrono::file_clock::to_sys(ftime));
            archive_entry_set_mtime(entry, mtime, 0);

            // Write the header. If it fails, log and free the entry.
            if (archive_write_header(a.get(), entry) != ARCHIVE_OK) {
                if (log)
                    log->append("Failed to write header for: " + path.string() +
                                " Error: " + archive_error_string(a.get()));
                archive_entry_free(entry);
                continue;
            }

            // If it is a regular file, stream its contents.
            if (fs::is_regular_file(fstatus)) {
                std::ifstream in_file(path, std::ios::binary);
                if (!in_file) {
                    if (log)
                        log->append("Failed to open file for reading: " + path.string());
                    archive_entry_free(entry);
                    continue;
                }
                const std::size_t buffer_size = 8192;
                char buffer[buffer_size];
                while (in_file) {
                    in_file.read(buffer, buffer_size);
                    std::streamsize bytes_read = in_file.gcount();
                    if (bytes_read > 0) {
                        if (archive_write_data(a.get(), buffer, static_cast<size_t>(bytes_read)) < 0) {
                            if (log)
                                log->append("Failed to write data for: " + path.string() +
                                            " Error: " + archive_error_string(a.get()));
                            break;
                        }
                    }
                }
                if (in_file.bad() && log) log->append("Error reading file: " + path.string());
            }

            if (archive_write_finish_entry(a.get()) != ARCHIVE_OK) if (log) log->append(std::format("Failed to finish entry for: {} Error: {}", path.string(), archive_error_string(a.get())));
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
