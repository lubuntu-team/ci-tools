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

#ifndef SOURCES_PARSER_H
#define SOURCES_PARSER_H

#include <string>
#include <vector>
#include <optional>
#include <cstring>
#include <set>

#include <QtCore/QJsonObject>
#include <QtCore/QJsonDocument>

// Structure to hold the required fields
struct PackageInfo {
    std::string Package;                   // Package name
    std::vector<std::string> Provides;     // Virtual packages provided
    std::string BuildDepends;              // Build dependencies (for source packages)
    std::optional<std::string> Source;     // Source package name (for binary packages)
    std::vector<std::string> Binary;

    // Nested structures for parsing dependencies
    struct ArchRestriction {
        bool enabled;
        std::string arch;
    };

    struct BuildRestriction {
        bool enabled;
        std::string condition;
    };

    struct ParsedRelation {
        std::string name;                                  // Dependency package name
        std::optional<std::string> archqual;               // Architecture qualifier
        std::optional<std::pair<std::string, std::string>> version; // Version relation and version
        std::optional<std::vector<ArchRestriction>> arch;  // Architecture restrictions
        std::optional<std::vector<std::vector<BuildRestriction>>> restrictions; // Build restrictions
    };

    // Parsed BuildDepends and Binary relations
    std::optional<std::vector<std::vector<ParsedRelation>>> BuildDependsParsed;
};

// Namespace to encapsulate the parser functionalities
namespace SourcesParser {
    // Function to download, decompress, and parse the Sources.gz data
    std::optional<std::vector<PackageInfo>> fetch_and_parse_sources(const std::string& url);

    // Function to download, decompress, and parse the Packages.gz data
    std::optional<std::vector<PackageInfo>> fetch_and_parse_packages(const std::string& url);

    // Function to parse dependency relations
    std::vector<std::vector<PackageInfo::ParsedRelation>> parse_relations(const std::string& raw);

    // Function to build dependency graph
    std::set<std::pair<std::string, std::string>> build_dependency_graph(
        const std::vector<PackageInfo>& sources,
        const std::vector<PackageInfo>& binaries);

    // Function to serialize dependency graph to JSON
    QString serialize_dependency_graph_to_json(const std::set<std::pair<std::string, std::string>>& graph);
} // namespace SourcesParser

#endif // SOURCES_PARSER_H
