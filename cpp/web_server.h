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

#ifndef WEB_SERVER_H
#define WEB_SERVER_H

#include "ci_database_objs.h"
#include "task_queue.h"

#include <QDateTime>
#include <QObject>
#include <QHttpServer>
#include <QMap>
#include <QSqlDatabase>
#include <QString>
#include <QSslServer>
#include <string>

class WebServer : public QObject {
    Q_OBJECT
public:
    explicit WebServer(QObject *parent = nullptr);
    bool start_server(quint16 port);

private:
    [[nodiscard]] std::map<QString, QString> parse_query_parameters(const QString &query);
    [[nodiscard]] bool validate_token(const QString& token);
    [[nodiscard]] QHttpServerResponse verify_session_token(const QHttpServerRequest &request, const QHttpHeaders &headers);
    void load_tokens(QSqlDatabase& p_db);

    QHttpServer http_server_;
    QSslServer ssl_server_;
    std::unique_ptr<TaskQueue> task_queue;
    std::jthread expire_tokens_thread_;
    std::jthread process_sources_thread_;

    QMap<int, QDateTime> _in_progress_tokens;
    QMap<QString, QDateTime> _active_tokens;
    QMap<QString, Person> _token_person;
};

#endif // WEB_SERVER_H
