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

#ifndef TEMPLATE_RENDERER_H
#define TEMPLATE_RENDERER_H

#include <string>
#include <map>
#include <vector>
#include <filesystem>

/**
 * This class provides two styles of rendering:
 *
 * 1) render_jinja(...) -- A naive Jinja-like expansion for loops/variables.
 * 2) render_with_inheritance(...) -- A minimal approach to handle
 *    {% extends "base.html" %} and {% block content %} usage, plus
 *    {{VARIABLE}} expansions.
 *
 * The "base.html" template is expected to contain something like:
 *     <html>... {{BLOCK content}} ...</html>
 * And the child template might do:
 *     {% extends "base.html" %}
 *     {% block content %}Hello world{% endblock %}
 */
class TemplateRenderer {
public:
    static std::string render_jinja(
        const std::string &tplPath,
        const std::map<std::string,std::string> &scalarContext,
        const std::map<std::string,
                       std::vector<std::map<std::string,std::string>>> &listContext
    );

    static std::string render_with_inheritance(
        const std::string &childTplName,
        const std::map<std::string,std::string> &scalarContext,
        const std::map<std::string,
                       std::vector<std::map<std::string,std::string>>> &listContext
    );

private:
    static std::string build_template_path(const std::string &tplName);
    static std::string file_get_contents(const std::string &path);

    // Filters
    static std::string apply_filter(const std::string &value, const std::string &filterPart);
    static std::string apply_all_filters(const std::string &valueWithFilters,
                                         const std::map<std::string,std::string> &ctx);

    // Conditionals
    static std::string expand_conditionals(std::string input,
                                           const std::map<std::string,std::string> &ctx);
    static bool evaluate_condition(const std::string &expr,
                                   const std::map<std::string,std::string> &ctx);

    // For loops
    static std::string expand_loops(const std::string &input,
                                    const std::map<std::string,std::string> &scalarContext,
                                    const std::map<std::string,
                                                   std::vector<std::map<std::string,std::string>>> &listContext);

    // Final expansions
    static std::string replace_variables(const std::string &input,
                                         const std::map<std::string,std::string> &context);

    // Helper: strip extraneous whitespace from final expansions
    static std::string strip_excess_whitespace(const std::string &str);

    static std::string get_variable_value(const std::string &var, const std::map<std::string, std::string> &ctx);
};

#endif // TEMPLATE_RENDERER_H
