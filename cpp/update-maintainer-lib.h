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

#ifndef UPDATE_MAINTAINER_LIB_H
#define UPDATE_MAINTAINER_LIB_H

#include <string>

//
// Update the "Maintainer" field in debian/control (or control.in)
// to a standard Ubuntu field, preserving the original field in
// XSBC-Original-Maintainer if needed.
//
void update_maintainer(const std::string &debian_directory, bool verbose);

#endif
