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

#include <atomic>
#include <cmath>
#include <chrono>
#include <mutex>
#include <thread>

#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QString>

// get_thread_connection and init_database
static std::mutex connection_mutex_;
static std::atomic<unsigned int> thread_id_counter{1};
static QString shared_database_path;

static int get_delay(int attempt) {
    return 10 * static_cast<int>(std::pow(1.5, attempt - 1));
}

QSqlDatabase get_thread_connection() {
    QString connection_name;
    bool passed = false;
    int attempt = 0;
    while (!passed) {
        QSqlDatabase thread_db;

        {
            std::lock_guard<std::mutex> lock(connection_mutex_);
            thread_local unsigned int thread_unique_id = thread_id_counter.fetch_add(1);
            connection_name = QString("CIConn_%1").arg(thread_unique_id);
            attempt++;
        }

        // Check if the connection already exists for this thread
        try {
            if (QSqlDatabase::contains(connection_name)) {
                QSqlDatabase db = QSqlDatabase::database(connection_name);
                db.setConnectOptions(QStringLiteral("QSQLITE_BUSY_TIMEOUT=5000"));
                if (!db.isOpen()) {
                    if (!db.open()) {
                        std::string last_error_text = db.lastError().text().toStdString();
                        if (last_error_text.contains("unable to open database file") |
                            last_error_text.contains("database is locked")) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(get_delay(attempt)));
                            continue;
                        }
                        throw std::runtime_error(std::format("Failed to open thread-specific database connection: {}", last_error_text));
                    }
                }
                return db;
            }

            thread_db = QSqlDatabase::addDatabase("QSQLITE", connection_name);
            thread_db.setDatabaseName(shared_database_path);
        } catch (...) {
            std::this_thread::sleep_for(std::chrono::milliseconds(get_delay(attempt)));
            continue;
        }

        if (!thread_db.open()) {
            const QString err = thread_db.lastError().text();
            if (err.contains("unable to open database file") || err.contains("database is locked"))
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(get_delay(attempt)));
                continue;
            }
            throw std::runtime_error("Failed to open new database connection: " + err.toStdString());
        }
        return thread_db;
    }
    return QSqlDatabase();
}

bool ci_query_exec(QSqlQuery* query, const QString query_string) {
    bool passed = false;
    int attempt = 0;
    while (!passed) {
        if (query_string.isEmpty()) passed = query->exec();
        else passed = query->exec(query_string);

        if (passed) return true;
        attempt++;

        QSqlError error = query->lastError();
        if (error.text().contains("database is locked")) std::this_thread::sleep_for(std::chrono::milliseconds(get_delay(attempt)));
        else if (error.text().contains("Parameter count mismatch")) {
            if (attempt > 15) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(get_delay(attempt)));
        } else break;
    }
    return false;
}

bool init_database(const QString& database_path) {
    shared_database_path = database_path;

    // Apply PRAGMAs
    {
        QSqlQuery pragma_query(get_thread_connection());
        ci_query_exec(&pragma_query, "PRAGMA journal_mode = WAL;");
        ci_query_exec(&pragma_query, "PRAGMA synchronous = NORMAL;");
        ci_query_exec(&pragma_query, "PRAGMA foreign_keys = ON;");
        ci_query_exec(&pragma_query, "PRAGMA wal_checkpoint(TRUNCATE);");
        ci_query_exec(&pragma_query, "VACUUM;");
    }

    // Run the schema creation (or migration) statements
    QStringList sql_statements = QString(R"(
        CREATE TABLE IF NOT EXISTS person (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            logo_url TEXT
        );

        CREATE TABLE IF NOT EXISTS person_token (
            id INTEGER PRIMARY KEY,
            person_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            expiry_date TEXT NOT NULL,
            FOREIGN KEY (person_id) REFERENCES person(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS package (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            large INTEGER NOT NULL DEFAULT 0,
            upstream_url TEXT NOT NULL,
            packaging_branch TEXT NOT NULL,
            packaging_url TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS release (
            id INTEGER PRIMARY KEY,
            version INTEGER NOT NULL UNIQUE,
            codename TEXT NOT NULL UNIQUE,
            isDefault INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS branch (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            upload_target TEXT NOT NULL,
            upload_target_ssh TEXT NOT NULL
        );

        INSERT INTO branch (name, upload_target, upload_target_ssh)
            SELECT 'unstable', 'ppa:lubuntu-ci/unstable-ci-proposed', 'ssh-ppa:lubuntu-ci/unstable-ci-proposed'
            WHERE NOT EXISTS (SELECT 1 FROM branch WHERE name='unstable');

        CREATE TABLE IF NOT EXISTS git_commit (
            id INTEGER PRIMARY KEY,
            commit_hash TEXT NOT NULL,
            commit_summary TEXT NOT NULL,
            commit_message TEXT NOT NULL,
            commit_datetime DATETIME NOT NULL,
            commit_author TEXT NOT NULL,
            commit_committer TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS packageconf (
            id INTEGER PRIMARY KEY,
            upstream_version TEXT,
            ppa_revision INTEGER,
            package_id INTEGER NOT NULL,
            release_id INTEGER NOT NULL,
            branch_id INTEGER NOT NULL,
            packaging_commit_id INTEGER,
            upstream_commit_id INTEGER,
            FOREIGN KEY (package_id) REFERENCES package(id) ON DELETE CASCADE,
            FOREIGN KEY (release_id) REFERENCES release(id) ON DELETE CASCADE,
            FOREIGN KEY (branch_id) REFERENCES branch(id) ON DELETE CASCADE,
            FOREIGN KEY (packaging_commit_id) REFERENCES git_commit(id) ON DELETE CASCADE,
            FOREIGN KEY (upstream_commit_id) REFERENCES git_commit(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS jobstatus (
            id INTEGER PRIMARY KEY,
            build_score INTEGER NOT NULL,
            name TEXT NOT NULL UNIQUE,
            display_name TEXT NOT NULL
        );

        INSERT OR IGNORE INTO jobstatus (build_score, name, display_name)
            VALUES
                (80, 'pull', 'Pull'),
                (70, 'tarball', 'Create Tarball'),
                (60, 'source_build', 'Source Build'),
                (50, 'upload', 'Upload'),
                (40, 'source_check', 'Source Check'),
                (30, 'build_check', 'Build Check'),
                (20, 'lintian', 'Lintian'),
                (10, 'britney', 'Britney');

        CREATE TABLE IF NOT EXISTS task (
            id INTEGER PRIMARY KEY,
            packageconf_id INTEGER NOT NULL,
            jobstatus_id INTEGER NOT NULL,
            queue_time INTEGER DEFAULT 0,
            start_time INTEGER DEFAULT 0,
            finish_time INTEGER DEFAULT 0,
            successful INTEGER,
            log TEXT,
            FOREIGN KEY (packageconf_id) REFERENCES packageconf(id),
            FOREIGN KEY (jobstatus_id) REFERENCES jobstatus(id)
        );

        CREATE TABLE IF NOT EXISTS packageconf_jobstatus_id (
            id INTEGER PRIMARY KEY,
            packageconf_id INTEGER NOT NULL,
            jobstatus_id INTEGER NOT NULL,
            task_id INTEGER NOT NULL,
            FOREIGN KEY (packageconf_id) REFERENCES packageconf(id),
            FOREIGN KEY (jobstatus_id) REFERENCES jobstatus(id),
            FOREIGN KEY (task_id) REFERENCES task(id)
        );

    )").split(';', Qt::SkipEmptyParts);

    {
        for (const QString &statement : sql_statements) {
            QSqlQuery query(get_thread_connection());
            QString trimmed = statement.trimmed();
            if (!trimmed.isEmpty() && !ci_query_exec(&query, trimmed)) {
                qDebug() << "Failed to execute SQL: " << trimmed
                         << "\nError: " << query.lastError().text();
                return false;
            }
        }
    }

    return true;
}
