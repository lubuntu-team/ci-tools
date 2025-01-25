/*
 *  A minimal Jinja2-like template engine in one file, supporting:
 *    - {% extends "base.html" %}
 *    - {% block content %} ... {% endblock %}
 *    - {{ scalarVariable }}
 *    - {% if expr %} ... {% elif expr %} ... {% else %} ... {% endif %}
 *    - {% for item in list %} ... {% endfor %}
 *    - Basic expression parsing with ==, !=, >, <, >=, <=
 *    - Simple filter usage: {{ var|add:-1 }}
 *
 *  Updated to support nested variable access using dot notation (e.g., repo.packaging_commit).
 *
 *  Copyright (C) 2024-2025 Simon Quigley <tsimonq2@ubuntu.com>
 */

#include "template_renderer.h"
#include <string>
#include <vector>
#include <map>
#include <regex>
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <stdexcept>
#include <cstdlib>
#include <algorithm>
#include <exception>
#include <shared_mutex>
#include <mutex>

namespace fs = std::filesystem;
static std::mutex file_mutex;

std::string TemplateRenderer::build_template_path(const std::string &tplName)
{
    if (!tplName.empty() && tplName.front() == '/') {
        return tplName;
    }
    return "templates/" + tplName;
}

std::string TemplateRenderer::file_get_contents(const std::string &path)
{
    std::unique_lock lock(file_mutex);
    try {
        fs::path rel(path);
        fs::path abs = fs::absolute(rel);
        auto open_file = [](const fs::path& file_path) -> std::ifstream {
            std::ifstream file(file_path, std::ios::in);
            if (!file) {
                throw std::ios_base::failure("File could not be opened: " + file_path.string());
            }
            return file;
        };

        std::ifstream file = open_file(abs);

        std::ostringstream contents;
        contents << file.rdbuf();
        return contents.str();
    } catch (const std::exception& e) {
        std::cerr << "Unable to get file contents in template_renderer: " << e.what() << "\n";
        return "";
    } catch (...) {
        std::cerr << "Unable to get file contents in template_renderer (unknown exception.)\n";
        return "";
    }
}

std::string TemplateRenderer::apply_filter(const std::string &value, const std::string &filterPart)
{
    size_t colonPos = filterPart.find(':');
    std::string filterName = (colonPos == std::string::npos)
        ? filterPart
        : filterPart.substr(0, colonPos);
    std::string filterArg = (colonPos == std::string::npos)
        ? ""
        : filterPart.substr(colonPos + 1);

    if (filterName == "add") {
        try {
            int original  = std::stoi(value);
            int increment = std::stoi(filterArg);
            return std::to_string(original + increment);
        } catch(...) {
            return value;
        }
    }
    // Additional filters can be added here.
    return value; // Unknown filter => pass through
}

std::string TemplateRenderer::apply_all_filters(const std::string &valueWithFilters,
                                                const std::map<std::string,std::string> &ctx)
{
    // Split on '|'
    std::vector<std::string> parts;
    size_t start = 0;
    while (true) {
        size_t pos = valueWithFilters.find('|', start);
        if (pos == std::string::npos) {
            parts.push_back(valueWithFilters.substr(start));
            break;
        }
        parts.push_back(valueWithFilters.substr(start, pos - start));
        start = pos + 1;
    }
    if (parts.empty()) {
        return "";
    }
    std::string varExpression = parts[0];
    std::string value = get_variable_value(varExpression, ctx);

    // Apply filters if any
    for (size_t i = 1; i < parts.size(); i++) {
        value = apply_filter(value, parts[i]);
    }
    return value;
}

bool TemplateRenderer::evaluate_condition(const std::string &expr,
                                          const std::map<std::string,std::string> &ctx)
{
    // Define helper lambdas
    auto trim = [](const std::string &s) -> std::string {
        size_t start = 0;
        while (start < s.size() && isspace(static_cast<unsigned char>(s[start]))) start++;
        size_t end = s.size();
        while (end > start && isspace(static_cast<unsigned char>(s[end - 1]))) end--;
        return s.substr(start, end - start);
    };

    auto isInteger = [&](const std::string &s) -> bool {
        if (s.empty()) return false;
        size_t start = (s[0] == '-') ? 1 : 0;
        for (size_t i = start; i < s.size(); ++i) {
            if (!isdigit(static_cast<unsigned char>(s[i]))) return false;
        }
        return true;
    };

    auto unquoteIfNeeded = [&](const std::string &tok) -> std::string {
        auto t = trim(tok);
        if (t.size() >= 2 &&
            ((t.front() == '\'' && t.back() == '\'') ||
             (t.front() == '\"' && t.back() == '\"'))) {
            return t.substr(1, t.size() - 2);
        }
        return t;
    };

    auto parse_token_value = [&](const std::string &rawToken) -> std::string {
        auto t = trim(rawToken);
        if (t.size() >= 2 && ((t.front() == '\'' && t.back() == '\'') ||
                              (t.front() == '\"' && t.back() == '\"'))) {
            // Literal string
            return unquoteIfNeeded(t);
        } else {
            // Apply filters
            return apply_all_filters(t, ctx);
        }
    };

    // Split the expression by 'and'
    std::vector<std::string> conditions;
    std::regex andRe("\\s+and\\s+");
    std::sregex_token_iterator it(expr.begin(), expr.end(), andRe, -1);
    std::sregex_token_iterator end;
    while (it != end) {
        conditions.push_back(trim(*it));
        ++it;
    }

    // Evaluate each sub-condition
    for (const auto &subExpr : conditions) {
        std::string e = trim(subExpr);
        if (e.empty()) continue;

        // Operators
        static std::vector<std::string> ops = {"==", "!=", "<=", ">=", ">", "<"};
        size_t opPos = std::string::npos;
        std::string opFound;
        for (const auto &cand : ops) {
            size_t p = e.find(cand);
            if (p != std::string::npos) {
                if (opPos == std::string::npos || p < opPos) {
                    opPos = p;
                    opFound = cand;
                }
            }
        }

        if (opPos == std::string::npos) {
            // No operator => check truthiness of var
            std::string val = parse_token_value(e);
            if (val.empty()) return false;
            continue;
        }

        std::string left = trim(e.substr(0, opPos));
        std::string right = trim(e.substr(opPos + opFound.size()));

        // Directly handle dot notation by using the entire composite key
        std::string lv = parse_token_value(left);
        std::string rv = parse_token_value(right);

        bool li = isInteger(lv);
        bool ri = isInteger(rv);
        bool result = false;

        if (li && ri) {
            int lnum = std::stoi(lv);
            int rnum = std::stoi(rv);
            if (opFound == "==") result = (lnum == rnum);
            else if (opFound == "!=") result = (lnum != rnum);
            else if (opFound == ">")  result = (lnum > rnum);
            else if (opFound == "<")  result = (lnum < rnum);
            else if (opFound == ">=") result = (lnum >= rnum);
            else if (opFound == "<=") result = (lnum <= rnum);
        } else {
            // String compare
            if (opFound == "==") result = (lv == rv);
            else if (opFound == "!=") result = (lv != rv);
            else if (opFound == ">")  result = (lv > rv);
            else if (opFound == "<")  result = (lv < rv);
            else if (opFound == ">=") result = (lv >= rv);
            else if (opFound == "<=") result = (lv <= rv);
        }

        if (!result) return false; // Short-circuit for 'and'
    }

    return true; // All sub-conditions passed
}

std::string TemplateRenderer::expand_conditionals(std::string input,
                                                  const std::map<std::string,std::string> &ctx)
{
    static std::regex ifOpenRe("\\{\\%\\s*if\\s+[^\\}]+\\%\\}");
    static std::regex ifCloseRe("\\{\\%\\s*endif\\s*\\%\\}");

    while (true) {
        // Gather all if-positions
        std::vector<size_t> ifPositions;
        {
            size_t searchStart = 0;
            while (true) {
                std::smatch mOpen;
                std::string sub = input.substr(searchStart);
                if (!std::regex_search(sub, mOpen, ifOpenRe)) {
                    break;
                }
                size_t posAbsolute = searchStart + mOpen.position(0);
                ifPositions.push_back(posAbsolute);
                searchStart = posAbsolute + mOpen.length(0);
            }
        }
        if (ifPositions.empty()) {
            break;
        }

        // The last one is the innermost
        size_t ifPos = ifPositions.back();

        {
            std::string sub2 = input.substr(ifPos);
            std::smatch mclose;
            if (!std::regex_search(sub2, mclose, ifCloseRe)) {
                // No matching endif
                break;
            }

            size_t closePosRelative = mclose.position(0);
            size_t ifClosePos = ifPos + closePosRelative;
            size_t blockLen = (ifClosePos - ifPos) + mclose.length(0);

            // Entire block
            std::string blockText = input.substr(ifPos, blockLen);

            // Main regex to match the entire if-endif block
            static std::regex mainRe(
                "\\{\\%\\s*if\\s+([^\\}]+)\\s*\\%\\}([\\s\\S]*?)\\{\\%\\s*endif\\s*\\%\\}"
            );
            std::smatch blockMatch;
            if (!std::regex_match(blockText, blockMatch, mainRe)) {
                break;
            }

            std::string condition = blockMatch[1].str();
            std::string innerBlock = blockMatch[2].str();

            // Parse out any {% elif ... %} / {% else %}
            struct ConditionBlock {
                std::string cond;   // Empty => else
                std::string content;
            };
            std::vector<ConditionBlock> blocks;
            blocks.emplace_back(ConditionBlock{ condition, "" });

            static std::regex elifElseRe("\\{\\%\\s*elif\\s+([^\\}]+)\\s*\\%\\}|\\{\\%\\s*else\\s*\\%\\}");
            size_t lastPos = 0;
            auto bBegin = std::sregex_iterator(innerBlock.begin(), innerBlock.end(), elifElseRe);
            auto bEnd   = std::sregex_iterator();
            for (auto i = bBegin; i != bEnd; ++i) {
                auto m2 = *i;
                size_t pos2 = m2.position(0);
                // Text up to pos2 is the previous block's content
                blocks.back().content.append(innerBlock.substr(lastPos, pos2 - lastPos));
                if (m2[1].matched) {
                    // Elif
                    blocks.emplace_back(ConditionBlock{ m2[1].str(), "" });
                } else {
                    // Else
                    blocks.emplace_back(ConditionBlock{ "", "" });
                }
                lastPos = pos2 + m2.length(0);
            }
            // Leftover
            if (!blocks.empty()) {
                blocks.back().content.append(innerBlock.substr(lastPos));
            }

            // Evaluate
            std::string finalText;
            bool used = false;
            for (auto &b : blocks) {
                if (b.cond.empty()) {
                    // Else
                    if (!used) {
                        finalText = b.content;
                    }
                    break;
                } else {
                    if (evaluate_condition(b.cond, ctx)) {
                        finalText = b.content;
                        used = true;
                        break;
                    }
                }
            }

            // Replace that block region with finalText
            input.replace(ifPos, blockLen, finalText);
        }
    }

    return input;
}

std::string TemplateRenderer::expand_loops(const std::string &input,
                                        const std::map<std::string,std::string> &scalarContext,
                                        const std::map<std::string,
                                                       std::vector<std::map<std::string,std::string>>> &listContext)
{
    std::string result = input;
    static std::regex loopRegex("\\{\\%\\s*for\\s+(\\S+)\\s+in\\s+(\\S+)\\s*\\%\\}([\\s\\S]*?)\\{\\%\\s*endfor\\s*\\%\\}");
    while (true) {
        std::smatch m;
        if (!std::regex_search(result, m, loopRegex)) {
            break;
        }
        std::string aliasName = m[1].str(); // e.g., 'repo'
        std::string arrayName = m[2].str(); // e.g., 'repos'
        std::string loopBody  = m[3].str();
        auto it = listContext.find(arrayName);
        if (it == listContext.end()) {
            // No such array => remove the block
            result.replace(m.position(0), m.length(0), "");
            continue;
        }
        std::string expanded;
        for (const auto &oneItem : it->second) {
            // Create a per-item scalar context with prefixed keys
            std::map<std::string, std::string> perItemScalarContext = scalarContext;
            for (const auto &kv : oneItem) {
                perItemScalarContext[aliasName + "." + kv.first] = kv.second;
            }

            std::string chunk = loopBody;

            // Expand conditionals with per-item scalar context
            chunk = expand_conditionals(chunk, perItemScalarContext);

            // Expand nested loops if any with per-item scalar context
            chunk = expand_loops(chunk, perItemScalarContext, listContext);

            // Final scalar expansions with per-item scalar context
            chunk = replace_variables(chunk, perItemScalarContext);

            // Remove excess whitespace
            chunk = strip_excess_whitespace(chunk);

            expanded += chunk;
        }
        result.replace(m.position(0), m.length(0), expanded);
    }
    return result;
}

std::string TemplateRenderer::replace_variables(const std::string &input,
    const std::map<std::string,std::string> &context)
{
    static std::regex varRe("\\{\\{\\s*(.*?)\\s*\\}\\}");
    std::string output;
    output.reserve(input.size());
    size_t lastPos = 0;
    auto begin = std::sregex_iterator(input.begin(), input.end(), varRe);
    auto end   = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
        auto match = *it;
        output.append(input, lastPos, match.position(0) - lastPos);
        std::string expr = match[1].str();

        // Directly apply all filters (which now handle composite keys)
        std::string value = apply_all_filters(expr, context);

        output.append(value);
        lastPos = match.position(0) + match.length(0);
    }
    output.append(input, lastPos);

    // Remove leftover {% ... %} if any
    static std::regex leftover("\\{\\%.*?\\%\\}");
    output = std::regex_replace(output, leftover, "");
    return output;
}

std::string TemplateRenderer::render_jinja(
    const std::string &tplPath,
    const std::map<std::string,std::string> &scalarContext,
    const std::map<std::string,
             std::vector<std::map<std::string,std::string>>> &listContext)
{
    std::string tpl = file_get_contents(tplPath);
    if (tpl.empty()) {
        return "<html><body><p>Template not found: " + tplPath + "</p></body></html>";
    }
    std::string step0 = expand_conditionals(tpl, scalarContext);
    std::string step1 = expand_loops(step0, scalarContext, listContext);
    std::string result = replace_variables(step1, scalarContext);
    return result;
}

std::string TemplateRenderer::render_with_inheritance(
    const std::string &childTplName,
    const std::map<std::string,std::string> &scalarContext,
    const std::map<std::string,
               std::vector<std::map<std::string,std::string>>> &listContext)
{
    // Load child template
    std::string childText = file_get_contents(build_template_path(childTplName));
    if (childText.empty()) {
        return "<html><body><h1>Missing child template:</h1>"
               + build_template_path(childTplName) + "</body></html>";
    }

    // Check for {% extends "base.html" %}
    static std::regex extendsRe("\\{\\%\\s*extends\\s*\"([^\"]+)\"\\s*\\%\\}");
    std::smatch exm;
    if (!std::regex_search(childText, exm, extendsRe)) {
        // No extends => just do expansions
        std::string step0 = expand_conditionals(childText, scalarContext);
        std::string step1 = expand_loops(step0, scalarContext, listContext);
        std::string result = replace_variables(step1, scalarContext);
        return result;
    }

    // If extends => load base
    std::string baseName = exm[1].str();
    std::string baseText = file_get_contents(build_template_path(baseName));
    if (baseText.empty()) {
        return "<html><body><h1>Missing base template:</h1>"
               + baseName + "</body></html>";
    }

    // Extract child block content
    static std::regex blockRe("\\{\\%\\s*block\\s+content\\s*\\%\\}([\\s\\S]*?)\\{\\%\\s*endblock\\s*\\%\\}");
    std::smatch blockMatch;
    std::string childBlock;
    if (std::regex_search(childText, blockMatch, blockRe)) {
        childBlock = blockMatch[1].str();
    }

    // Process loops first, which handle their own conditionals with loop variables
    std::string expandedChildBlock = expand_loops(childBlock, scalarContext, listContext);
    // Then process any conditionals outside loops
    expandedChildBlock = expand_conditionals(expandedChildBlock, scalarContext);
    // Finally, replace variables in the child block
    expandedChildBlock = replace_variables(expandedChildBlock, scalarContext);

    // Replace {{BLOCK content}} in base with expanded child block
    const std::string marker = "{{BLOCK content}}";
    size_t pos = baseText.find(marker);
    if (pos != std::string::npos) {
        baseText.replace(pos, marker.size(), expandedChildBlock);
    }

    // Replace variables in the entire base template (to handle {{PAGE_TITLE}})
    baseText = replace_variables(baseText, scalarContext);

    // Remove any remaining {% ... %} tags
    static std::regex leftover("\\{\\%.*?\\%\\}");
    baseText = std::regex_replace(baseText, leftover, "");

    return baseText;
}

std::string TemplateRenderer::strip_excess_whitespace(const std::string &str) {
    // Remove leading/trailing spaces and unify consecutive whitespace into single spaces
    std::string result;
    result.reserve(str.size());
    bool prevSpace = false;
    for (char c: str) {
        if (isspace(static_cast<unsigned char>(c))) {
            if (!prevSpace) {
                result += ' ';
                prevSpace = true;
            }
        } else {
            result += c;
            prevSpace = false;
        }
    }
    // Trim leading and trailing spaces
    size_t start = 0;
    while (start < result.size() && isspace(static_cast<unsigned char>(result[start]))) {
        start++;
    }
    size_t end = result.size();
    while (end > start && isspace(static_cast<unsigned char>(result[end - 1]))) {
        end--;
    }
    return result.substr(start, end - start);
}

std::string TemplateRenderer::get_variable_value(const std::string &var,
                                                 const std::map<std::string, std::string> &ctx) {
    auto it = ctx.find(var);
    if (it != ctx.end()) {
        return it->second;
    }
    return "";
}
