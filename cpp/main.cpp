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

#include <QCoreApplication>
#include <iostream>
#include "web_server.h"

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);

    WebServer server;
    // You can pick 80 if running as root or with CAP_NET_BIND_SERVICE
    // or 8080 if unprivileged
    if (!server.start_server(8080)) {
        std::cerr << "[ERROR] Failed to start server on port 8080\n";
        return 1;
    }

    return app.exec();
}
