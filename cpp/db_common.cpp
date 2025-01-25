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

QSqlDatabase get_thread_connection() {
    std::lock_guard<std::mutex> lock(connection_mutex_);
    thread_local unsigned int thread_unique_id = thread_id_counter.fetch_add(1);
    QString connection_name = QString("CIConn_%1").arg(thread_unique_id);

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
    thread_db.setDatabaseName(shared_database_path);

    if (!thread_db.open()) {
        throw std::runtime_error("Failed to open new database connection for thread: " + thread_db.lastError().text().toStdString());
    }

    return thread_db;
}

bool ci_query_exec(QSqlQuery* query) {
    bool passed = false;
    int attempt = 0;
    while (passed) {
        passed = query->exec();
        if (passed) return true;
        attempt++;

        QSqlError error = query->lastError();
        if (error.text().contains("database is locked")) {
            int delay = 1000 * static_cast<int>(std::pow(2, attempt - 1));
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
        } else break;
    }
    return false;
}

bool init_database(const QString& database_path) {
    shared_database_path = database_path;

    // Apply PRAGMAs
    {
        QSqlQuery pragma_query(get_thread_connection());
        pragma_query.exec("PRAGMA journal_mode = WAL;");
        pragma_query.exec("PRAGMA synchronous = NORMAL;");
        pragma_query.exec("PRAGMA foreign_keys = ON;");
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
            if (!trimmed.isEmpty() && !query.exec(trimmed)) {
                qDebug() << "Failed to execute SQL: " << trimmed
                         << "\nError: " << query.lastError().text();
                return false;
            }
        }
    }

    return true;
}
