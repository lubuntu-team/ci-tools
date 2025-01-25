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

#include "sources_parser.h"
#include "utilities.h"

#include "/usr/include/archive.h"
#include <archive_entry.h>
#include <curl/curl.h>

#include <algorithm>
#include <cctype>
#include <iostream>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <map>
#include <set>
#include <vector>
#include <optional>
#include <fstream> // Added to resolve ofstream errors
#include <set>
#include <ranges>

#include <QtCore/QJsonArray>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonObject>



namespace SourcesParser {

// Function to write data fetched by libcurl into a std::vector<char>
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t totalSize = size * nmemb;
    auto* buffer = static_cast<std::vector<char>*>(userp);
    buffer->insert(buffer->end(), static_cast<char*>(contents), static_cast<char*>(contents) + totalSize);
    return totalSize;
}

// Function to parse dependency relations
std::vector<std::vector<PackageInfo::ParsedRelation>> parse_relations(const std::string& raw) {
    std::vector<std::vector<PackageInfo::ParsedRelation>> result;

    // Split by comma to get top-level dependencies
    std::regex comma_sep_RE(R"(\s*,\s*)");
    std::sregex_token_iterator comma_it(raw.begin(), raw.end(), comma_sep_RE, -1);
    std::sregex_token_iterator comma_end;

    for (; comma_it != comma_end; ++comma_it) {
        std::string top_dep = comma_it->str();
        // Split by pipe to get alternative dependencies
        std::regex pipe_sep_RE(R"(\s*\|\s*)");
        std::sregex_token_iterator pipe_it(top_dep.begin(), top_dep.end(), pipe_sep_RE, -1);
        std::sregex_token_iterator pipe_end;

        std::vector<PackageInfo::ParsedRelation> alternatives;

        for (; pipe_it != pipe_end; ++pipe_it) {
            std::string dep = pipe_it->str();
            // Remove any version constraints or architecture qualifiers
            size_t pos_space = dep.find(' ');
            size_t pos_paren = dep.find('(');
            size_t pos = std::string::npos;
            if (pos_space != std::string::npos && pos_paren != std::string::npos) {
                pos = std::min(pos_space, pos_paren);
            }
            else if (pos_space != std::string::npos) {
                pos = pos_space;
            }
            else if (pos_paren != std::string::npos) {
                pos = pos_paren;
            }

            if (pos != std::string::npos) {
                dep = dep.substr(0, pos);
            }

            // Trim whitespace
            dep.erase(dep.find_last_not_of(" \t\n\r\f\v") + 1);
            dep.erase(0, dep.find_first_not_of(" \t\n\r\f\v"));

            // Handle architecture qualifiers (e.g., "libc6 (>= 2.27)")
            std::regex arch_RE(R"(^([a-zA-Z0-9+\-\.]+)(?:\s*\(\s*([a-zA-Z]+)\s*([<>=]+)\s*([0-9a-zA-Z:\-+~.]+)\s*\))?$)");
            std::smatch match;
            if (std::regex_match(dep, match, arch_RE)) {
                PackageInfo::ParsedRelation pr;
                pr.name = match[1];
                if (match[2].matched && match[3].matched && match[4].matched) {
                    // If architecture qualifier exists, store it
                    pr.archqual = match[2].str() + match[3].str() + match[4].str();
                }
                if (match[3].matched && match[4].matched) {
                    // Store version constraints
                    pr.version = std::make_pair(match[3].str(), match[4].str());
                }
                alternatives.push_back(pr);
            }
            else {
                // If regex does not match, include raw dependency without qualifiers
                dep = remove_suffix(dep, ":any");
                dep = remove_suffix(dep, ":native");
                PackageInfo::ParsedRelation pr;
                pr.name = dep;
                alternatives.push_back(pr);
                std::cerr << "Warning: Cannot parse dependency relation \"" << dep << "\", returning it raw.\n";
            }
        }

        if (!alternatives.empty()) {
            result.push_back(alternatives);
        }
    }

    return result;
}

// Function to download, decompress, and parse the Sources.gz data
std::optional<std::vector<PackageInfo>> fetch_and_parse_sources(const std::string& url) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Failed to initialize CURL.\n";
        return std::nullopt;
    }

    std::vector<char> downloadedData;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &downloadedData);
    // Follow redirects if any
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    // Set a user agent
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "SourcesParser/1.0");

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "CURL download error (Sources.gz): " << curl_easy_strerror(res) << "\n";
        curl_easy_cleanup(curl);
        return std::nullopt;
    }

    curl_easy_cleanup(curl);

    // Initialize libarchive
    struct archive* a = archive_read_new();
    archive_read_support_filter_gzip(a);
    archive_read_support_format_raw(a);

    if (archive_read_open_memory(a, downloadedData.data(), downloadedData.size()) != ARCHIVE_OK) {
        std::cerr << "Failed to open Sources.gz archive: " << archive_error_string(a) << "\n";
        archive_read_free(a);
        return std::nullopt;
    }

    struct archive_entry* entry;
    std::string decompressedData;

    // Read all entries (though there should typically be only one)
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        const void* buff;
        size_t size;
        la_int64_t offset;

        while (true) {
            int r = archive_read_data_block(a, &buff, &size, &offset);
            if (r == ARCHIVE_EOF)
                break;
            if (r != ARCHIVE_OK) {
                std::cerr << "Error during decompression (Sources.gz): " << archive_error_string(a) << "\n";
                archive_read_free(a);
                return std::nullopt;
            }
            decompressedData.append(static_cast<const char*>(buff), size);
        }
    }

    archive_read_free(a);

    // Parse the decompressed data
    std::vector<PackageInfo> packages;
    std::istringstream stream(decompressedData);
    std::string line;
    PackageInfo currentPackage;
    bool in_entry = false;

    while (std::getline(stream, line)) {
        if (line.empty()) {
            if (in_entry && !currentPackage.Package.empty()) {
                // Finalize BuildDependsParsed
                currentPackage.BuildDependsParsed = parse_relations(currentPackage.BuildDepends);
                packages.push_back(currentPackage);
                currentPackage = PackageInfo();
                in_entry = false;
            }
            continue;
        }

        in_entry = true;

        if (line.find("Build-Depends:") == 0) {
            currentPackage.BuildDepends = line.substr(strlen("Build-Depends: "));
            // Continue reading lines that start with a space or tab
            while (std::getline(stream, line)) {
                if (line.empty() || (!std::isspace(static_cast<unsigned char>(line[0]))))
                    break;
                currentPackage.BuildDepends += " " + line.substr(1);
            }
            // If the last read line is not a continuation, process it in the next iteration
            if (!line.empty() && !std::isspace(static_cast<unsigned char>(line[0]))) {
                stream.seekg(-static_cast<int>(line.length()) - 1, std::ios_base::cur);
            }
            continue;
        }

        if (line.find("Binary:") == 0) {
            std::string binary_str;
            binary_str = line.substr(strlen("Binary: "));
            // Continue reading lines that start with a space or tab
            while (std::getline(stream, line)) {
                if (line.empty() || (!std::isspace(static_cast<unsigned char>(line[0]))))
                    break;
                binary_str += " " + line.substr(1);
            }
            // If the last read line is not a continuation, process it in the next iteration
            if (!line.empty() && !std::isspace(static_cast<unsigned char>(line[0]))) {
                stream.seekg(-static_cast<int>(line.length()) - 1, std::ios_base::cur);
            }
            currentPackage.Binary = split_string(binary_str, ", ");
            continue;
        }

        // Extract Package
        if (line.find("Package:") == 0) {
            currentPackage.Package = line.substr(strlen("Package: "));
            continue;
        }

        // Extract Provides (if any)
        if (line.find("Provides:") == 0) {
            std::string provides_line = line.substr(strlen("Provides: "));
            // Split by commas
            std::regex comma_sep_RE(R"(\s*,\s*)");
            std::sregex_token_iterator provides_it(provides_line.begin(), provides_line.end(), comma_sep_RE, -1);
            std::sregex_token_iterator provides_end;

            for (; provides_it != provides_end; ++provides_it) {
                std::string provide = provides_it->str();
                // Extract the package name before any space or '('
                size_t pos_space = provide.find(' ');
                size_t pos_paren = provide.find('(');
                size_t pos = std::string::npos;
                if (pos_space != std::string::npos && pos_paren != std::string::npos) {
                    pos = std::min(pos_space, pos_paren);
                }
                else if (pos_space != std::string::npos) {
                    pos = pos_space;
                }
                else if (pos_paren != std::string::npos) {
                    pos = pos_paren;
                }

                if (pos != std::string::npos) {
                    provide = provide.substr(0, pos);
                }

                // Trim whitespace
                provide.erase(provide.find_last_not_of(" \t\n\r\f\v") + 1);
                provide.erase(0, provide.find_first_not_of(" \t\n\r\f\v"));

                if (!provide.empty()) {
                    currentPackage.Provides.push_back(provide);
                }
            }

            continue;
        }
    }

    // Add the last package if the file doesn't end with a blank line
    if (in_entry && !currentPackage.Package.empty()) {
        // Finalize BuildDependsParsed
        currentPackage.BuildDependsParsed = parse_relations(currentPackage.BuildDepends);
        packages.push_back(currentPackage);
    }

    return packages;
}

// Function to download, decompress, and parse the Packages.gz data
std::optional<std::vector<PackageInfo>> fetch_and_parse_packages(const std::string& url) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Failed to initialize CURL.\n";
        return std::nullopt;
    }

    std::vector<char> downloadedData;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &downloadedData);
    // Follow redirects if any
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    // Set a user agent
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "SourcesParser/1.0");

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "CURL download error (Packages.gz): " << curl_easy_strerror(res) << "\n";
        curl_easy_cleanup(curl);
        return std::nullopt;
    }

    curl_easy_cleanup(curl);

    // Initialize libarchive
    struct archive* a = archive_read_new();
    archive_read_support_filter_gzip(a);
    archive_read_support_format_raw(a);

    if (archive_read_open_memory(a, downloadedData.data(), downloadedData.size()) != ARCHIVE_OK) {
        std::cerr << "Failed to open Packages.gz archive: " << archive_error_string(a) << "\n";
        archive_read_free(a);
        return std::nullopt;
    }

    struct archive_entry* entry;
    std::string decompressedData;

    // Read all entries (though there should typically be only one)
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        const void* buff;
        size_t size;
        la_int64_t offset;

        while (true) {
            int r = archive_read_data_block(a, &buff, &size, &offset);
            if (r == ARCHIVE_EOF)
                break;
            if (r != ARCHIVE_OK) {
                std::cerr << "Error during decompression (Packages.gz): " << archive_error_string(a) << "\n";
                archive_read_free(a);
                return std::nullopt;
            }
            decompressedData.append(static_cast<const char*>(buff), size);
        }
    }

    archive_read_free(a);

    // Parse the decompressed data
    std::vector<PackageInfo> packages;
    std::istringstream stream(decompressedData);
    std::string line;
    PackageInfo currentPackage;
    bool in_entry = false;

    while (std::getline(stream, line)) {
        if (line.empty()) {
            if (in_entry && !currentPackage.Package.empty()) {
                packages.push_back(currentPackage);
                currentPackage = PackageInfo();
                in_entry = false;
            }
            continue;
        }

        in_entry = true;

        // Extract Package
        if (line.find("Package:") == 0) {
            currentPackage.Package = line.substr(strlen("Package: "));
            continue;
        }

        // Extract Source
        if (line.find("Source:") == 0) {
            currentPackage.Source = line.substr(strlen("Source: "));
            continue;
        }

        // Extract Provides
        if (line.find("Provides:") == 0) {
            std::string provides_line = line.substr(strlen("Provides: "));
            // Split by commas
            std::regex comma_sep_RE(R"(\s*,\s*)");
            std::sregex_token_iterator provides_it(provides_line.begin(), provides_line.end(), comma_sep_RE, -1);
            std::sregex_token_iterator provides_end;

            for (; provides_it != provides_end; ++provides_it) {
                std::string provide = provides_it->str();
                // Extract the package name before any space or '('
                size_t pos_space = provide.find(' ');
                size_t pos_paren = provide.find('(');
                size_t pos = std::string::npos;
                if (pos_space != std::string::npos && pos_paren != std::string::npos) {
                    pos = std::min(pos_space, pos_paren);
                }
                else if (pos_space != std::string::npos) {
                    pos = pos_space;
                }
                else if (pos_paren != std::string::npos) {
                    pos = pos_paren;
                }

                if (pos != std::string::npos) {
                    provide = provide.substr(0, pos);
                }

                // Trim whitespace
                provide.erase(provide.find_last_not_of(" \t\n\r\f\v") + 1);
                provide.erase(0, provide.find_first_not_of(" \t\n\r\f\v"));

                if (!provide.empty()) {
                    currentPackage.Provides.push_back(provide);
                }
            }

            continue;
        }

        // Any other fields are ignored for now
    }

    // Add the last package if the file doesn't end with a blank line
    if (in_entry && !currentPackage.Package.empty()) {
        packages.push_back(currentPackage);
    }

    return packages;
}

std::set<std::pair<std::string, std::string>> build_dependency_graph(
    const std::vector<PackageInfo>& sources,
    const std::vector<PackageInfo>& binaries) {

    // Map of virtual package to real binary package(s)
    std::map<std::string, std::vector<std::string>> virtual_to_real;
    // Set of all real binary package names
    std::set<std::string> real_binary_packages;
    // Map of binary package to its source package
    std::map<std::string, std::string> binary_to_source;

    // Populate binary_to_source mapping and virtual_to_real
    for (const auto& source_pkg : sources) {
        for (const auto& binary_pkg : source_pkg.Binary) {
            binary_to_source[binary_pkg] = source_pkg.Package;
            real_binary_packages.insert(binary_pkg);
        }
    }
    for (const auto& binary_pkg : binaries) {
        if (binary_pkg.Source.has_value()) {
            binary_to_source[binary_pkg.Package] = binary_pkg.Source.value();
        }
        real_binary_packages.insert(binary_pkg.Package);

        // Process Provides
        for (const auto& provide : binary_pkg.Provides) {
            virtual_to_real[provide].push_back(binary_pkg.Package);
        }
    }

    // Dependency graph as a set of edges (dependency -> package)
    std::set<std::pair<std::string, std::string>> graph;

    for (const auto& pkg : sources) {
        if (!pkg.BuildDependsParsed.has_value())
            continue; // Skip if no build dependencies

        for (const auto& or_deps : pkg.BuildDependsParsed.value()) {
            // For each set of alternative dependencies (logical OR)
            for (const auto& dep : or_deps) {
                std::string dep_name = dep.name;
                // If dep.archqual exists, append it with ':'
                if (dep.archqual.has_value())
                    dep_name += ":" + dep.archqual.value();

                // If dep_name is a virtual package, map it to real binary package(s)
                if (virtual_to_real.find(dep_name) != virtual_to_real.end()) {
                    for (const auto& real_pkg : virtual_to_real[dep_name]) {
                        // Map binary dependency to source package
                        if (binary_to_source.find(real_pkg) != binary_to_source.end()) {
                            std::string source_dep = binary_to_source[real_pkg];
                            // Avoid self-dependency
                            if (source_dep != pkg.Package) {
                                graph.emplace(source_dep, pkg.Package); // Reversed edge
                            }
                        }
                        else {
                            std::cerr << "Warning: Binary package \"" << real_pkg << "\" provided by \"" 
                                      << dep_name << "\" does not map to any source package.\n";
                        }
                    }
                }
                else if (real_binary_packages.find(dep_name) != real_binary_packages.end()) {
                    // Direct binary dependency
                    if (binary_to_source.find(dep_name) != binary_to_source.end()) {
                        std::string source_dep = binary_to_source[dep_name];
                        // Avoid self-dependency
                        if (source_dep != pkg.Package) {
                            graph.emplace(source_dep, pkg.Package); // Reversed edge
                        }
                    }
                    else {
                        std::cerr << "Warning: Binary dependency \"" << dep_name << "\" does not map to any source package.\n";
                    }
                }
            }
        }
    }

    // Transitive reduction: Collect edges to remove first
    std::vector<std::pair<std::string, std::string>> edges_to_remove;

    // Build adjacency list from the graph
    std::map<std::string, std::set<std::string>> adj;
    for (const auto& edge : graph) {
        adj[edge.first].insert(edge.second);
    }

    for (const auto& [u, neighbors] : adj) {
        for (const auto& v : neighbors) {
            if (adj.find(v) != adj.end()) {
                for (const auto& w : adj[v]) {
                    if (adj[u].find(w) != adj[u].end()) {
                        edges_to_remove.emplace_back(u, w);
                    }
                }
            }
        }
    }

    // Now remove the collected edges
    for (const auto& edge : edges_to_remove) {
        graph.erase(edge);
        adj[edge.first].erase(edge.second);
    }

    return graph;
}

QString serialize_dependency_graph_to_json(const std::set<std::pair<std::string, std::string>>& graph) {
    // Check if the graph is empty
    if (graph.empty()) {
        std::cerr << "Warning: Dependency graph is empty." << std::endl;
        return "{}"; // Return empty JSON object
    }

    // Build adjacency list where key is dependency and value is list of packages that depend on it
    std::map<std::string, QJsonArray> adjacency;
    for (const auto& edge : graph) {
        if (!edge.first.empty() && !edge.second.empty()) {
            adjacency[edge.first].append(QString::fromStdString(edge.second));
        }
    }

    // Convert to QJsonObject
    QJsonObject jsonObj;
    for (const auto& [dep, dependents] : adjacency) {
        jsonObj[QString::fromStdString(dep)] = dependents;
    }

    // Convert to JSON string
    QJsonDocument doc(jsonObj);
    return QString(doc.toJson(QJsonDocument::Compact));
}

} // namespace SourcesParser
