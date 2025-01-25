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

#include "db_common.h"
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <atomic>
#include <mutex>

std::mutex connection_mutex_;
static std::atomic<unsigned int> thread_id_counter{10};

QSqlDatabase get_thread_connection() {
    std::lock_guard<std::mutex> lock(connection_mutex_);
    thread_local unsigned int thread_unique_id = thread_id_counter.fetch_add(1);
    QString connection_name = QString("LubuntuCIConnection_%1").arg(thread_unique_id);

    // Check if the connection already exists for this thread
    if (QSqlDatabase::contains(connection_name)) {
        QSqlDatabase db = QSqlDatabase::database(connection_name);
        if (!db.isOpen()) {
            if (!db.open()) {
                throw std::runtime_error("Failed to open thread-specific database connection: " + db.lastError().text().toStdString());
            }
        }
        return db;
    }

    QSqlDatabase thread_db = QSqlDatabase::addDatabase("QSQLITE", connection_name);
    thread_db.setDatabaseName("/srv/lubuntu-ci/repos/ci-tools/lubuntu_ci.db");

    if (!thread_db.open()) {
        throw std::runtime_error("Failed to open new database connection for thread: " + thread_db.lastError().text().toStdString());
    }

    return thread_db;
}
