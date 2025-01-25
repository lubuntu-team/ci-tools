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

#include "web_server.h"
#include "utilities.h"
#include "sources_parser.h"
#include "naive_bayes_classifier.h"

// Qt includes
#include <QtHttpServer/QHttpServer>
#include <QtHttpServer/QHttpServerRequest>
#include <QtHttpServer/QHttpServerResponse>
#include <QTcpServer>
#include <QDir>
#include <QFile>
#include <QDateTime>
#include <QJsonArray>
#include <QDebug>
#include <QtConcurrent/QtConcurrent>
#include <QFuture>
#include <QSqlQuery>
#include <QSqlError>

// C++ includes
#include <iostream>
#include <filesystem>
#include <regex>
#include <string>
#include <sstream>
#include <ranges>
#include <set>
#include <vector>
#include <format> // C++20/23 for std::format

// Launchpad includes
#include "launchpad.h"
#include "archive.h"
#include "person.h"
#include "distribution.h"
#include "distro_series.h"
#include "source_package_publishing_history.h"
#include "build.h"
#include "binary_package_publishing_history.h"

// Local includes
#include "lubuntuci_lib.h"
#include "template_renderer.h"

constexpr QHttpServerResponder::StatusCode StatusCodeFound = QHttpServerResponder::StatusCode::Found;

static std::string timestamp_now()
{
    return QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss.zzz").toStdString();
}

WebServer::WebServer(QObject *parent) : QObject(parent) {}

[[nodiscard]] std::map<QString, QString> WebServer::parse_query_parameters(const QString &query) {
    return query
        .split('&') // Split by '&' into key-value pairs
        | std::views::filter([](const QString &param) { return param.contains('='); }) // Only valid pairs
        | std::views::transform([](const QString &param) {
            const auto keyValue = param.split('=');
            return std::pair{keyValue[0], keyValue[1]}; // Return a key-value pair
        })
        | std::ranges::to<std::map<QString, QString>>(); // Collect the pairs into a map
}

[[nodiscard]] bool WebServer::validate_token(const QString& token) {
    // Always 64 characters
    if (token.size() != 64) return false;
    // Can't validate the active token if there aren't any
    if (_active_tokens.isEmpty()) return false;
    // Always present in active_tokens, and not expired
    auto it = _active_tokens.find(token);
    if (it != _active_tokens.end() && it.value() >= QDateTime::currentDateTime()) return true;
    else {
        _active_tokens.erase(it);

        auto person_it = _token_person.find(token);
        if (person_it != _token_person.end()) _token_person.erase(person_it);

        return false;
    }
}

[[nodiscard]] QHttpServerResponse WebServer::verify_session_token(const QHttpServerRequest &request, const QHttpHeaders &headers) {
    const QByteArray cookie_header = headers.value(QHttpHeaders::WellKnownHeader::Cookie).toByteArray();
    const QUrl request_url = request.url();
    const QString base_url = request_url.scheme() + "://" + request_url.host() +
                             (request_url.port() == -1 ? "" : ':' + QString::number(request_url.port()));
    const QString current_path = request_url.path();

    for (const auto &cookie : cookie_header.split(';')
                            | std::views::transform([](const QByteArray &cookie) { return cookie.trimmed(); })
                            | std::views::filter([](const QByteArray &cookie) { return cookie.startsWith("auth_token="); })) {
        if (!validate_token(QString::fromUtf8(cookie.mid(sizeof("auth_token=") - 1)))) break;
        return QHttpServerResponse(QHttpServerResponder::StatusCode::Ok);
    }

    QHttpServerResponse bad_response(StatusCodeFound);
    QHttpHeaders bad_response_headers;
    bad_response_headers.replaceOrAppend(QHttpHeaders::WellKnownHeader::Location, "/unauthorized?base_url=" + base_url + "&redirect_to=" + current_path);
    bad_response.setHeaders(bad_response_headers);

    return bad_response;
}

bool WebServer::start_server(quint16 port) {
    std::optional<std::shared_ptr<launchpad>> global_lp_opt;
    launchpad* global_lp = nullptr;
    auto lp_opt = launchpad::login();
    if (!lp_opt.has_value()) {
        std::cerr << "Failed to authenticate with Launchpad.\n";
        return false;
    }
    auto lp = lp_opt.value().get();
    auto ubuntu_opt = lp->distributions["ubuntu"];
    if (!ubuntu_opt.has_value()) {
        std::cerr << "Failed to retrieve ubuntu.\n";
        return false;
    }
    distribution ubuntu = ubuntu_opt.value();

    auto lubuntu_ci_opt = lp->people["lubuntu-ci"];
    if (!lubuntu_ci_opt.has_value()) {
        std::cerr << "Failed to retrieve lubuntu-ci.\n";
        return false;
    }
    person lubuntu_ci = lubuntu_ci_opt.value();

    auto regular_opt = lubuntu_ci.getPPAByName(ubuntu, "unstable-ci");
    if (!regular_opt.has_value()) {
        std::cerr << "Failed to retrieve regular PPA.\n";
        return false;
    }
    archive regular = regular_opt.value();

    auto proposed_opt = lubuntu_ci.getPPAByName(ubuntu, "unstable-ci-proposed");
    if (!proposed_opt.has_value()) {
        std::cerr << "Failed to retrieve proposed PPA.\n";
        return false;
    }
    archive proposed = proposed_opt.value();

    std::shared_ptr<PackageConf> _tmp_pkg_conf = std::make_shared<PackageConf>();
    std::shared_ptr<LubuntuCI> lubuntuci = std::make_shared<LubuntuCI>();
    std::vector<std::shared_ptr<PackageConf>> all_repos = lubuntuci->list_known_repos();
    task_queue = std::make_unique<TaskQueue>(10);
    static const std::map<std::string, std::shared_ptr<JobStatus>> job_statuses = lubuntuci->cilogic.get_job_statuses();
    task_queue->start();

    // Load initial tokens
    {
        QSqlQuery load_tokens(lubuntuci->cilogic.get_thread_connection());
        load_tokens.prepare("SELECT person.id, person.username, person.logo_url, person_token.token, person_token.expiry_date FROM person INNER JOIN person_token ON person.id = person_token.person_id");
        load_tokens.exec();
        while (load_tokens.next()) {
            int person_id = load_tokens.value(0).toInt();
            QString username = load_tokens.value(1).toString();
            QString logo_url = load_tokens.value(2).toString();
            QString token = load_tokens.value(3).toString();
            QDateTime expiry_date = QDateTime::fromString(load_tokens.value(4).toString(), Qt::ISODate);

            Person person(person_id, username.toStdString(), logo_url.toStdString());
            _active_tokens[token] = expiry_date;
            _token_person[token] = person;
        }
    }

    expire_tokens_thread_ = std::jthread(run_task_every, 60, [this, lubuntuci] {
        QSqlQuery expired_tokens(lubuntuci->cilogic.get_thread_connection());
        QString current_time = QDateTime::currentDateTime().toString(Qt::ISODate);

        expired_tokens.prepare("DELETE FROM person_token WHERE expiry_date < :current_time");
        expired_tokens.bindValue(":current_time", QDateTime::currentDateTime().toString(Qt::ISODate));
        expired_tokens.exec();
        for (auto it = _active_tokens.begin(); it != _active_tokens.end();) {
            if (it.value() <= QDateTime::currentDateTime()) it = _active_tokens.erase(it);
            else ++it;
        }
        for (auto it = _token_person.begin(); it != _token_person.end();) {
            if (!_active_tokens.contains(it.key())) it = _token_person.erase(it);
            else ++it;
        }
    });

    process_sources_thread_ = std::jthread(run_task_every, 10, [this, all_repos, proposed, lubuntuci] {
        for (auto pkgconf : all_repos) {
            if (!pkgconf->can_check_source_upload()) { continue; }

            task_queue->enqueue(
                job_statuses.at("source_check"),
                [this, proposed](std::shared_ptr<Log> log) mutable {
                    std::shared_ptr<PackageConf> pkgconf = log->get_task_context()->get_parent_packageconf();
                    std::string package_version = pkgconf->upstream_version + "-0ubuntu0~ppa" + std::to_string(pkgconf->ppa_revision);
                    bool found_in_ppa = false;
                    for (auto spph : proposed.getPublishedSources("", "", std::nullopt, true, true, "", pkgconf->package->name, "", package_version)) {
                        found_in_ppa = true;
                        break;
                    }

                    if (!found_in_ppa) {
                        throw std::runtime_error("Not found in the PPA.");
                    }
                },
                pkgconf
            );

            lubuntuci->cilogic.sync(pkgconf);
        }
    });

    ////////////////////////////////////////////////////////////////
    // /unauthorized?base_url=<base_url>&redirect_to=<redirect_to>
    ////////////////////////////////////////////////////////////////
    http_server_.route("/unauthorized", [this, lubuntuci](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
        // Extract data up front
        auto query = req.query();
        QString base_url = query.queryItemValue("base_url");
        QString redirect_to = query.hasQueryItem("redirect_to") ? query.queryItemValue("redirect_to") : "";

        std::mt19937 generator(std::random_device{}());
        std::uniform_int_distribution<int> distribution(100, 999);

        return QtConcurrent::run([this, base_url, redirect_to, gen = std::move(generator), dist = std::move(distribution)]() mutable -> QHttpServerResponse {
            int auth_identifier;
            do {
                auth_identifier = dist(gen);
            } while (_in_progress_tokens.contains(auth_identifier));
            _in_progress_tokens[auth_identifier] = QDateTime::currentDateTime().addSecs(60 * 60);

            QString form_data = QString(R"(
                <html>
                    <head>
                        <title>OpenID Redirect</title>
                    </head>
                    <body>
                        <form id="openid-form" action="https://login.ubuntu.com/+openid" method="POST">
                            <input type="hidden" name="openid.mode" value="checkid_setup" />
                            <input type="hidden" name="openid.identity" value="http://specs.openid.net/auth/2.0/identifier_select" />
                            <input type="hidden" name="openid.return_to" value="%1/authcallback?auth_identifier=%2&redirect_to=%3" />
                            <input type="hidden" name="openid.ns" value="http://specs.openid.net/auth/2.0" />
                            <input type="hidden" name="openid.claimed_id" value="http://specs.openid.net/auth/2.0/identifier_select" />
                            <input type="hidden" name="openid.realm" value="%1" />
                            <input type="hidden" name="openid.ns.sreg" value="http://openid.net/extensions/sreg/1.1" />
                            <input type="hidden" name="openid.sreg.required" value="nickname" />
                            <input type="hidden" name="openid.ns.ax" value="http://openid.net/srv/ax/1.0" />
                            <input type="hidden" name="openid.ax.mode" value="fetch_request" />
                            <input type="hidden" name="openid.ax.required" value="mail_ao,name_ao,mail_son,name_son" />
                            <input type="hidden" name="openid.ax.type.mail_ao" value="http://axschema.org/contact/email" />
                            <input type="hidden" name="openid.ax.type.name_ao" value="http://axschema.org/namePerson/friendly" />
                            <input type="hidden" name="openid.ax.type.mail_son" value="http://schema.openid.net/contact/email" />
                            <input type="hidden" name="openid.ax.type.name_son" value="http://schema.openid.net/namePerson/friendly" />
                            <input type="hidden" name="openid.ns.lp" value="http://ns.launchpad.net/2007/openid-teams" />
                            <input type="hidden" name="openid.lp.query_membership" value="ubuntu-qt-code" />
                            <input type="hidden" name="form_id" value="openid_redirect_form" />
                        </form>
                        <script type="text/javascript">
                            document.getElementById('openid-form').submit();
                        </script>
                    </body>
                </html>
            )").arg(base_url).arg(auth_identifier).arg(redirect_to);

            return QHttpServerResponse("text/html", QByteArray(form_data.toUtf8()));
        });
    });

    /////////////////
    // /authcallback
    /////////////////
    http_server_.route("/authcallback", [this, lubuntuci](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
        // Extract data up front
        auto query = req.query();
        QString base_url = query.queryItemValue("base_url");
        QString redirect_to = query.hasQueryItem("redirect_to") ? query.queryItemValue("redirect_to") : "";
        std::map<QString, QString> params = parse_query_parameters(req.query().toString());

        return QtConcurrent::run([=, this]() {
            std::set<std::string> only_care_about = {"auth_identifier", "openid.ax.value.name_ao.1",
                                                     "openid.lp.is_member", "openid.mode"};

            bool has_correct_params = true;
            int found_only_care_about = 0;
            std::string username;
            for (auto [key, value] : params) {
                if (!only_care_about.contains(key.toStdString())) continue;

                if (key == "auth_identifier") {
                    found_only_care_about++;
                    if (value.size() != 3) has_correct_params = false;
                    else if (!_in_progress_tokens.contains(value.toInt())) has_correct_params = false;
                    else if (_in_progress_tokens[value.toInt()] <= QDateTime::currentDateTime()) {
                        _in_progress_tokens.remove(value.toInt());
                        has_correct_params = false;
                    } else {
                        _in_progress_tokens.remove(value.toInt());
                    }
                } else if (key == "openid.ax.value.name_ao.1") {
                    found_only_care_about++;
                    username = value.toStdString();
                } else if (key == "openid.lp.is_member") {
                    found_only_care_about++;
                    if (value.isEmpty()) has_correct_params = false;
                    else if (!value.contains("ubuntu-qt-code")) has_correct_params = false;
                } else if (key == "openid.mode") {
                    found_only_care_about++;
                    if (value != "id_res") has_correct_params = false;
                }
            }

            if (!has_correct_params || (found_only_care_about != only_care_about.size())) {
                std::map<std::string, std::string> scalar_context;
                std::map<std::string, std::vector<std::map<std::string, std::string>>> list_context;
                std::string failed_auth_html = TemplateRenderer::render_with_inheritance(
                    "ope.html",
                    scalar_context,
                    list_context
                );

                return QHttpServerResponse("text/html", QByteArray(failed_auth_html.c_str(), (int)failed_auth_html.size()));
            }

            // Create the new token
            QString token;
            {
                std::mt19937 generator(std::random_device{}());
                std::uniform_int_distribution<int> distribution(0, 255);
                std::ostringstream tok;
                for (size_t i = 0; i < 32; ++i) tok << std::hex << std::setw(2) << std::setfill('0') << distribution(generator);
                token = QString::fromStdString(tok.str());
            }

            // Find the existing Person object if there is one
            Person person;
            bool found_key_bool = false;
            QString found_key;
            for (auto it = _token_person.begin(); it != _token_person.end(); ++it) {
                if (it.value().username == username) {
                    person = it.value();
                    found_key = it.key();
                    found_key_bool = true;
                    break;
                }
            }

            if (found_key_bool) {
                _token_person.remove(found_key);
            } else {
                QSqlQuery get_person(lubuntuci->cilogic.get_thread_connection());
                get_person.prepare("SELECT id, username, logo_url FROM person WHERE username = ?");
                get_person.bindValue(0, QString::fromStdString(username));
                if (!get_person.exec()) { qDebug() << "Error executing SELECT query for person:" << get_person.lastError(); }

                if (get_person.next()) {
                    person = Person(get_person.value(0).toInt(), get_person.value(1).toString().toStdString(),
                                    get_person.value(2).toString().toStdString());
                } else {
                    QSqlQuery insert_person(lubuntuci->cilogic.get_thread_connection());
                    insert_person.prepare("INSERT INTO person (username, logo_url) VALUES (?, ?)");
                    insert_person.bindValue(0, QString::fromStdString(username));
                    insert_person.bindValue(1, QString::fromStdString("https://api.launchpad.net/devel/~" + username + "/logo"));
                    if (!insert_person.exec()) { qDebug() << "Error executing INSERT query for person:" << insert_person.lastError(); }

                    QVariant last_id = insert_person.lastInsertId();
                    if (last_id.isValid()) {
                        person = Person(last_id.toInt(), username, "https://api.launchpad.net/devel/~" + username + "/logo");
                    }
                }
            }

            // Insert the token into the sets and database
            QDateTime one_day = QDateTime::currentDateTime().addSecs(24 * 60 * 60);
            _token_person.insert(token, person);
            _active_tokens.insert(token, one_day);

            {
                QSqlQuery insert_token(lubuntuci->cilogic.get_thread_connection());
                insert_token.prepare("INSERT INTO person_token (person_id, token, expiry_date) VALUES (?, ?, ?)");
                insert_token.bindValue(0, person.id);
                insert_token.bindValue(1, token);
                insert_token.bindValue(2, one_day.toString(Qt::ISODate));
                if (!insert_token.exec()) { qDebug() << "Error executing INSERT query for token:" << insert_token.lastError(); }
            }

            QString final_html = QString(R"(
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <title>Redirecting...</title>
                    <script> window.location.href = "%1"; </script>
                </head>
                <body>
                    <h1>Success!</h1>
                    <p>Redirecting... If you are not redirected automatically, <a href="%1">click here</a>.</p>
                </body>
                </html>
            )").arg(redirect_to);
            QHttpServerResponse good_redirect("text/html", final_html.toUtf8());
            QHttpHeaders good_redirect_headers;
            QString url_safe_token = QUrl::toPercentEncoding(token);
            good_redirect_headers.replaceOrAppend(QHttpHeaders::WellKnownHeader::SetCookie,
                                                  "auth_token=" + url_safe_token + "; HttpOnly; SameSite=Strict");
            good_redirect.setHeaders(good_redirect_headers);
            return good_redirect;
        });
    });

    //////////////////////////////////////////
    // Route "/"
    //////////////////////////////////////////
    http_server_.route("/", [this, lubuntuci](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
        {
            QHttpServerResponse session_response = verify_session_token(req, req.headers());
            if (session_response.statusCode() == StatusCodeFound) return QtConcurrent::run([response = std::move(session_response)]() mutable { return std::move(response); });
        }
        auto query = req.query();
        int page = query.queryItemValue("page").isEmpty() ? 1 : query.queryItemValue("page").toInt();
        int per_page = query.queryItemValue("per_page").isEmpty() ? 30 : query.queryItemValue("per_page").toInt();
        std::string sort_by = query.queryItemValue("sort_by").isEmpty()
                              ? "id"
                              : query.queryItemValue("sort_by").toStdString();
        std::string sort_order = query.queryItemValue("sort_order").isEmpty()
                                 ? "asc"
                                 : query.queryItemValue("sort_order").toStdString();

        return QtConcurrent::run([=, this]() {
            auto all_repos = lubuntuci->list_known_repos();
            int total_size = static_cast<int>(all_repos.size());
            int total_pages = (per_page > 0)
                              ? (total_size + per_page - 1) / per_page
                              : 1;

            auto repos = lubuntuci->list_known_repos(page, per_page, sort_by, sort_order);
            if (repos.empty() && total_size == 0) {
                std::string err_html = R"(
<html>
<head><title>No repos</title></head>
<body>
<h1>ERROR: No repositories found!</h1>
</body>
</html>
)";
                return QHttpServerResponse("text/html", QByteArray(err_html.c_str(), (int)err_html.size()));
            }

            std::map<std::string, std::string> scalar_context = {
                {"PAGE_TITLE", "Lubuntu CI Home"},
                {"page", std::to_string(page)},
                {"sort_by", sort_by},
                {"sort_order", sort_order},
                {"total_pages", std::to_string(total_pages)}
            };
            std::map<std::string, std::vector<std::map<std::string, std::string>>> list_context;

            std::vector<std::map<std::string, std::string>> reposVec;
            for (const auto &r : repos) {
                std::map<std::string, std::string> item;
                std::string packaging_commit_str;
                std::string upstream_commit_str;

                if (r->packaging_commit) {
                    std::string commit_summary = r->packaging_commit->commit_summary;
                    if (commit_summary.size() > 40) {
                        commit_summary = commit_summary.substr(0, 37) + "...";
                    }
                    packaging_commit_str = r->packaging_commit->commit_hash.substr(0, 7) +
                        std::format(" ({:%Y-%m-%d %H:%M:%S %Z})<br />", r->packaging_commit->commit_datetime) +
                        commit_summary;
                }
                if (r->upstream_commit) {
                    std::string commit_summary = r->upstream_commit->commit_summary;
                    if (commit_summary.size() > 40) {
                        commit_summary = commit_summary.substr(0, 37) + "...";
                    }
                    upstream_commit_str = r->upstream_commit->commit_hash.substr(0, 7) +
                        std::format(" ({:%Y-%m-%d %H:%M:%S %Z})<br />", r->upstream_commit->commit_datetime) +
                        commit_summary;
                }

                std::string packaging_commit_url_str = (r->package ? r->package->packaging_browser : "") +
                                                       (r->packaging_commit ? r->packaging_commit->commit_hash : "");
                std::string upstream_commit_url_str = (r->package ? r->package->upstream_browser : "") +
                                                      (r->upstream_commit ? r->upstream_commit->commit_hash : "");

                item["id"] = std::to_string(r->id);
                item["name"] = r->package->name;
                item["branch_name"] = r->branch->name;
                item["codename"] = r->release->codename;
                item["packaging_commit"] = packaging_commit_str;
                item["packaging_commit_url"] = packaging_commit_url_str;
                item["upstream_commit"] = upstream_commit_str;
                item["upstream_commit_url"] = upstream_commit_url_str;

                // For each job in the map, fetch the real task and set a CSS class accordingly.
                for (auto const & [job_name, job_ptr] : job_statuses) {
                    auto t = r->get_task_by_jobstatus(job_ptr);
                    if (t) {
                        std::string css_class = "bg-secondary";  // default

                        if (t->finish_time > 0) {
                            css_class = t->successful ? "bg-success" : "bg-danger";
                        } else if (t->start_time > 0) {
                            css_class = "bg-warning";  // started but not finished
                        } else {
                            css_class = "bg-info";     // queued but not started
                        }

                        item[job_name + "_class"] = css_class;
                    } else {
                        item[job_name + "_class"] = "";
                    }
                }

                reposVec.push_back(item);
            }
            list_context["repos"] = reposVec;

            std::string final_html = TemplateRenderer::render_with_inheritance(
                "home.html",
                scalar_context,
                list_context
            );

            return QHttpServerResponse("text/html", QByteArray(final_html.c_str(), (int)final_html.size()));
        });
    });

    //////////////////////////////////////////
    // /pull?repo=<id>
    //////////////////////////////////////////
    http_server_.route("/pull", [this, lubuntuci](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
        {
            QHttpServerResponse session_response = verify_session_token(req, req.headers());
            if (session_response.statusCode() == StatusCodeFound) return QtConcurrent::run([response = std::move(session_response)]() mutable { return std::move(response); });
        }
        // Extract data up front
        auto query = req.query();
        QString repo_string = query.queryItemValue("repo");
        // We'll store them in normal copyable types
        std::string repoStr = repo_string.toStdString();

        // Return the concurrency
        return QtConcurrent::run([=, this]() {
            if (repo_string.isEmpty() || !repo_string.toInt(nullptr, 10)) {
                std::string msg = "No valid repo specified.";
                return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
            }
            int repo = std::stoi(repoStr);

            std::string msg = lubuntuci->cilogic.queue_pull_tarball({ lubuntuci->cilogic.get_packageconf_by_id(repo) }, task_queue, job_statuses);
            return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
        });
    });

    //////////////////////////////////////////
    // /build?repo=<id>
    //////////////////////////////////////////
    http_server_.route("/build", [this, lubuntuci](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
        auto query = req.query();
        QString repo_string = query.queryItemValue("repo");
        std::string repoStr = repo_string.toStdString();

        return QtConcurrent::run([=, this]() {
            if (repo_string.isEmpty() || !repo_string.toInt(nullptr, 10)) {
                std::string msg = "No valid repo specified.";
                return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
            }
            int repo = std::stoi(repoStr);

            std::shared_ptr<PackageConf> pkgconf = lubuntuci->cilogic.get_packageconf_by_id(repo);
            static const std::map<std::string, std::shared_ptr<JobStatus>> job_statuses = lubuntuci->cilogic.get_job_statuses();

            task_queue->enqueue(
                job_statuses.at("source_build"),
                [this, lubuntuci](std::shared_ptr<Log> log) mutable {
                    std::shared_ptr<PackageConf> pkgconf = log->get_task_context()->get_parent_packageconf();
                    auto [build_ok, changes_files] = lubuntuci->cilogic.build_project(pkgconf, log);
                    if (build_ok) {
                        task_queue->enqueue(
                            job_statuses.at("upload"),
                            [lubuntuci, changes_files](std::shared_ptr<Log> log2) mutable {
                                std::shared_ptr<PackageConf> pkgconf2 = log2->get_task_context()->get_parent_packageconf();
                                bool upload_ok = lubuntuci->cilogic.upload_and_lint(pkgconf2, changes_files, false, log2);
                                (void)upload_ok;
                            },
                            pkgconf
                        );
                    }
                },
                pkgconf
            );
            std::string msg = "Build queued";
            return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
        });
    });

    //////////////////////////////////////////
    // /logs?repo=foo
    //////////////////////////////////////////
    http_server_.route("/logs", [this, lubuntuci](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
        {
            QHttpServerResponse session_response = verify_session_token(req, req.headers());
            if (session_response.statusCode() == StatusCodeFound) return QtConcurrent::run([response = std::move(session_response)]() mutable { return std::move(response); });
        }
        auto query = req.query();
        std::string repo = query.queryItemValue("repo").toStdString();

        return QtConcurrent::run([=, this]() {
            if (repo.empty()) {
                std::string msg = "<html><body>No repo specified.</body></html>";
                return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
            }
            std::string log_content = lubuntuci->get_repo_log(repo);

            std::map<std::string, std::vector<std::map<std::string, std::string>>> list_context;
            std::map<std::string,std::string> context;
            context["title"] = "Logs for " + repo;

            std::string body;
            body += "<h2>Logs: " + repo + "</h2>";
            body += "<pre class=\"bg-white p-2\">" + log_content + "</pre>";

            context["BODY_CONTENT"] = body;

            std::string final_html = TemplateRenderer::render_with_inheritance(
                "base.html",
                context,
                list_context
            );
            if (final_html.empty()) {
                final_html = "<html><body><h1>Log Output</h1><pre>"
                             + log_content + "</pre></body></html>";
            }
            return QHttpServerResponse("text/html", QByteArray(final_html.c_str(), (int)final_html.size()));
        });
    });

    //////////////////////////////////////////
    // /pull-selected?repos=<ids>
    //////////////////////////////////////////
    http_server_.route("/pull-selected", [this, lubuntuci, all_repos](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
        {
            QHttpServerResponse session_response = verify_session_token(req, req.headers());
            if (session_response.statusCode() == StatusCodeFound) return QtConcurrent::run([response = std::move(session_response)]() mutable { return std::move(response); });
        }
        auto query = req.query();
        std::string repos_str = query.queryItemValue("repos").toStdString();

        return QtConcurrent::run([=, this]() {
            if (repos_str.empty()) {
                std::string msg = "<div class='text-danger'>No repositories specified for pull.</div>";
                return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
            }

            std::set<int> repos = std::ranges::to<std::set<int>>(
                split_string(repos_str, "%2C")
                | std::views::filter([](const std::string& s) {
                    return !s.empty() && std::ranges::all_of(s, ::isdigit);
                })
                | std::views::transform([](const std::string& s) {
                    return std::stoi(s);
                })
            );

            std::string msg = lubuntuci->cilogic.queue_pull_tarball(lubuntuci->cilogic.get_packageconfs_by_ids(repos), task_queue, job_statuses);
            return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
        });
    });

    //////////////////////////////////////////
    // /build-selected?repos=foo,bar,baz
    //////////////////////////////////////////
    http_server_.route("/build-selected", [this, lubuntuci](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
        {
            QHttpServerResponse session_response = verify_session_token(req, req.headers());
            if (session_response.statusCode() == StatusCodeFound) return QtConcurrent::run([response = std::move(session_response)]() mutable { return std::move(response); });
        }
        auto query = req.query();
        std::string repos_str = query.queryItemValue("repos").toStdString();

        return QtConcurrent::run([=, this]() {
            if (repos_str.empty()) {
                std::string msg = "<div class='text-danger'>No repositories specified for build.</div>";
                return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
            }

            std::set<int> repos = std::ranges::to<std::set<int>>(
                split_string(repos_str, "%2C")
                | std::views::filter([](const std::string& s) {
                    return !s.empty() && std::ranges::all_of(s, ::isdigit);
                })
                | std::views::transform([](const std::string& s) {
                    return std::stoi(s);
                })
            );
            std::vector<std::shared_ptr<PackageConf>> pkgconfs = lubuntuci->cilogic.get_packageconfs_by_ids(repos);

            if (repos.empty()) {
                std::string msg = "No valid repositories specified for build: " + repos_str;
                return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
            }

            std::string msg;
            static const std::map<std::string, std::shared_ptr<JobStatus>> job_statuses = lubuntuci->cilogic.get_job_statuses();

            for (auto pkgconf : pkgconfs) {
                task_queue->enqueue(
                    job_statuses.at("source_build"),
                    [this, lubuntuci](std::shared_ptr<Log> log) {
                        std::shared_ptr<PackageConf> pkgconf = log->get_task_context()->get_parent_packageconf();
                        auto [build_ok, changes_files] = lubuntuci->cilogic.build_project(pkgconf, log);
                        if (build_ok) {
                            static const std::map<std::string, std::shared_ptr<JobStatus>> job_statuses2 = lubuntuci->cilogic.get_job_statuses();
                            task_queue->enqueue(
                                job_statuses2.at("upload"),
                                [lubuntuci, changes_files](std::shared_ptr<Log> log2) mutable {
                                    std::shared_ptr<PackageConf> pkgconf2 = log2->get_task_context()->get_parent_packageconf();
                                    bool upload_ok = lubuntuci->cilogic.upload_and_lint(pkgconf2, changes_files, false, log2);
                                    (void)upload_ok;
                                },
                                pkgconf
                            );
                        }
                    },
                    pkgconf
                );
                msg += "Build queued\n";
            }
            return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
        });
    });

    //////////////////////////////////////////
    // /pull-and-build-selected?repos=foo,bar,baz
    //////////////////////////////////////////
    http_server_.route("/pull-and-build-selected", [this, lubuntuci](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
        {
            QHttpServerResponse session_response = verify_session_token(req, req.headers());
            if (session_response.statusCode() == StatusCodeFound) return QtConcurrent::run([response = std::move(session_response)]() mutable { return std::move(response); });
        }
        auto query = req.query();
        std::string repos_str = query.queryItemValue("repos").toStdString();

        return QtConcurrent::run([=, this]() {
            if (repos_str.empty()) {
                std::string msg = "<div class='text-danger'>No repositories specified for build and pull.</div>";
                return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
            }

            std::set<int> repos = std::ranges::to<std::set<int>>(
                split_string(repos_str, "%2C")
                | std::views::filter([](const std::string& s) {
                    return !s.empty() && std::ranges::all_of(s, ::isdigit);
                })
                | std::views::transform([](const std::string& s) {
                    return std::stoi(s);
                })
            );
            std::vector<std::shared_ptr<PackageConf>> pkgconfs = lubuntuci->cilogic.get_packageconfs_by_ids(repos);

            if (repos.empty()) {
                std::string msg = "<div class='text-danger'>No valid repositories specified for build and pull.</div>";
                return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
            }

            std::string msg;
            static const std::map<std::string, std::shared_ptr<JobStatus>> job_statuses = lubuntuci->cilogic.get_job_statuses();
            std::set<std::pair<std::string, std::shared_ptr<PackageConf>>> encountered;
            for (auto pkgconf : pkgconfs) {
                bool is_ghost_pull = true;
                std::shared_ptr<PackageConf> first_pkgconf;
                auto it = std::find_if(encountered.begin(), encountered.end(),
                       [pkgconf](const std::pair<std::string, std::shared_ptr<PackageConf>>& elem) {
                           return elem.first == pkgconf->package->name;
                       });
                if (it == encountered.end()) {
                    is_ghost_pull = false;
                    encountered.insert({pkgconf->package->name, pkgconf});
                } else {
                    first_pkgconf = it->second;
                }

                task_queue->enqueue(
                    job_statuses.at("pull"),
                    [this, lubuntuci, first_pkgconf, is_ghost_pull](std::shared_ptr<Log> log) {
                        std::shared_ptr<PackageConf> pkgconf = log->get_task_context()->get_parent_packageconf();
                        bool pull_ok;
                        if (is_ghost_pull) {
                            pull_ok = true;
                            pkgconf->packaging_commit = first_pkgconf->packaging_commit;
                            pkgconf->upstream_commit = first_pkgconf->upstream_commit;
                            lubuntuci->cilogic.sync(pkgconf);
                        } else {
                            pull_ok = lubuntuci->cilogic.pull_project(pkgconf, log);
                        }
                        if (pull_ok) {
                            static const std::map<std::string, std::shared_ptr<JobStatus>> job_statuses2 = lubuntuci->cilogic.get_job_statuses();
                            task_queue->enqueue(
                                job_statuses2.at("tarball"),
                                [this, lubuntuci, is_ghost_pull](std::shared_ptr<Log> log2) {
                                    std::shared_ptr<PackageConf> pkgconf2 = log2->get_task_context()->get_parent_packageconf();
                                    bool tarball_ok = is_ghost_pull ? true : lubuntuci->cilogic.create_project_tarball(pkgconf2, log2);
                                    if (tarball_ok) {
                                        static const std::map<std::string, std::shared_ptr<JobStatus>> job_statuses3 = lubuntuci->cilogic.get_job_statuses();
                                        task_queue->enqueue(
                                            job_statuses3.at("source_build"),
                                            [this, lubuntuci](std::shared_ptr<Log> log3) {
                                                std::shared_ptr<PackageConf> pkgconf3 = log3->get_task_context()->get_parent_packageconf();
                                                auto [build_ok, changes_files] = lubuntuci->cilogic.build_project(pkgconf3, log3);
                                                if (build_ok) {
                                                    static const std::map<std::string, std::shared_ptr<JobStatus>> job_statuses4 = lubuntuci->cilogic.get_job_statuses();
                                                    task_queue->enqueue(
                                                        job_statuses4.at("upload"),
                                                        [lubuntuci, changes_files](std::shared_ptr<Log> log4) mutable {
                                                            std::shared_ptr<PackageConf> pkgconf4 = log4->get_task_context()->get_parent_packageconf();
                                                            bool upload_ok = lubuntuci->cilogic.upload_and_lint(pkgconf4, changes_files, false, log4);
                                                            (void)upload_ok;
                                                        },
                                                        pkgconf3
                                                    );
                                                }
                                            },
                                            pkgconf2
                                        );
                                    }
                                },
                                pkgconf
                            );
                        }
                    },
                    pkgconf
                );
            }
            return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
        });
    });

    //////////////////////////////////////////
    // /pull-all
    //////////////////////////////////////////
    http_server_.route("/pull-all", [this, lubuntuci, all_repos](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
        {
            QHttpServerResponse session_response = verify_session_token(req, req.headers());
            if (session_response.statusCode() == StatusCodeFound) return QtConcurrent::run([response = std::move(session_response)]() mutable { return std::move(response); });
        }
        return QtConcurrent::run([=, this]() {
            std::string msg = lubuntuci->cilogic.queue_pull_tarball(all_repos, task_queue, job_statuses);

            return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
        });
    });

    //////////////////////////////////////////
    // /build-all
    //////////////////////////////////////////
    http_server_.route("/build-all", [this, lubuntuci](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
        {
            QHttpServerResponse session_response = verify_session_token(req, req.headers());
            if (session_response.statusCode() == StatusCodeFound) return QtConcurrent::run([response = std::move(session_response)]() mutable { return std::move(response); });
        }
        return QtConcurrent::run([=, this]() {
            auto repos = lubuntuci->list_known_repos();
            std::string msg;
            static const std::map<std::string, std::shared_ptr<JobStatus>> job_statuses = lubuntuci->cilogic.get_job_statuses();

            for (const auto& r : repos) {
                task_queue->enqueue(
                    job_statuses.at("source_build"),
                    [this, lubuntuci](std::shared_ptr<Log> log) {
                        std::shared_ptr<PackageConf> pkgconf = log->get_task_context()->get_parent_packageconf();
                        auto [build_ok, changes_files] = lubuntuci->cilogic.build_project(pkgconf, log);
                        if (build_ok) {
                            static const std::map<std::string, std::shared_ptr<JobStatus>> job_statuses2 = lubuntuci->cilogic.get_job_statuses();
                            task_queue->enqueue(
                                job_statuses2.at("upload"),
                                [lubuntuci, changes_files](std::shared_ptr<Log> log2) {
                                    std::shared_ptr<PackageConf> pkgconf2 = log2->get_task_context()->get_parent_packageconf();
                                    bool upload_ok = lubuntuci->cilogic.upload_and_lint(pkgconf2, changes_files, false, log2);
                                    (void)upload_ok;
                                },
                                pkgconf
                            );
                        }
                    },
                    r
                );
                msg += "Build for " + r->package->name + "queued\n";
            }
            return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
        });
    });

    //////////////////////////////////////////
    // /pull-and-build-all
    //////////////////////////////////////////
    http_server_.route("/pull-and-build-all", [this, lubuntuci](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
        {
            QHttpServerResponse session_response = verify_session_token(req, req.headers());
            if (session_response.statusCode() == StatusCodeFound) return QtConcurrent::run([response = std::move(session_response)]() mutable { return std::move(response); });
        }
        return QtConcurrent::run([=, this]() {
            auto repos = lubuntuci->list_known_repos();
            std::string msg;
            static const std::map<std::string, std::shared_ptr<JobStatus>> job_statuses = lubuntuci->cilogic.get_job_statuses();

            std::set<std::pair<std::string, std::shared_ptr<PackageConf>>> encountered;
            for (auto repo : repos) {
                bool is_ghost_pull = true;
                std::shared_ptr<PackageConf> first_pkgconf;
                auto it = std::find_if(encountered.begin(), encountered.end(),
                    [repo](const std::pair<std::string, std::shared_ptr<PackageConf>>& elem) {
                        return elem.first == repo->package->name;
                    }
                );
                if (it == encountered.end()) {
                    is_ghost_pull = false;
                    encountered.insert({repo->package->name, repo});
                } else {
                    first_pkgconf = it->second;
                }

                task_queue->enqueue(
                    job_statuses.at("pull"),
                    [this, repo, lubuntuci, first_pkgconf, is_ghost_pull](std::shared_ptr<Log> log) {
                        std::shared_ptr<PackageConf> pkgconf = log->get_task_context()->get_parent_packageconf();
                        bool pull_ok;
                        if (is_ghost_pull) {
                            pull_ok = true;
                            pkgconf->packaging_commit = first_pkgconf->packaging_commit;
                            pkgconf->upstream_commit = first_pkgconf->upstream_commit;
                            lubuntuci->cilogic.sync(pkgconf);
                        } else {
                            auto packaging_commit = pkgconf->packaging_commit;
                            auto upstream_commit = pkgconf->upstream_commit;
                            bool _pull_ok = lubuntuci->cilogic.pull_project(pkgconf, log);
                            if ((packaging_commit != pkgconf->packaging_commit) ||
                                (upstream_commit != pkgconf->upstream_commit)) {
                                pull_ok = true;
                            } else {
                                pull_ok = false;
                            }
                        }

                        if (pull_ok) {
                            static const std::map<std::string, std::shared_ptr<JobStatus>> job_statuses2 = lubuntuci->cilogic.get_job_statuses();
                            task_queue->enqueue(
                                job_statuses2.at("tarball"),
                                [this, repo, lubuntuci, is_ghost_pull](std::shared_ptr<Log> log2) {
                                    std::shared_ptr<PackageConf> pkgconf2 = log2->get_task_context()->get_parent_packageconf();
                                    bool tarball_ok = is_ghost_pull ? true : lubuntuci->cilogic.create_project_tarball(pkgconf2, log2);
                                    if (tarball_ok) {
                                        static const std::map<std::string, std::shared_ptr<JobStatus>> job_statuses3 = lubuntuci->cilogic.get_job_statuses();
                                        task_queue->enqueue(
                                            job_statuses3.at("source_build"),
                                            [this, repo, lubuntuci](std::shared_ptr<Log> log3) {
                                                std::shared_ptr<PackageConf> pkgconf3 = log3->get_task_context()->get_parent_packageconf();
                                                auto [build_ok, changes_files] = lubuntuci->cilogic.build_project(pkgconf3, log3);
                                                if (build_ok) {
                                                    static const std::map<std::string, std::shared_ptr<JobStatus>> job_statuses4 = lubuntuci->cilogic.get_job_statuses();
                                                    task_queue->enqueue(
                                                        job_statuses4.at("upload"),
                                                        [lubuntuci, changes_files](std::shared_ptr<Log> log4) {
                                                            std::shared_ptr<PackageConf> pkgconf4 = log4->get_task_context()->get_parent_packageconf();
                                                            bool upload_ok = lubuntuci->cilogic.upload_and_lint(pkgconf4, changes_files, false, log4);
                                                            (void)upload_ok;
                                                        },
                                                        pkgconf3
                                                    );
                                                }
                                            },
                                            pkgconf2
                                        );
                                    }
                                },
                                pkgconf
                            );
                        }
                    },
                    repo
                );
            }
            return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
        });
    });

    //////////////////////////////////////////
    // Serve static files from /static/<arg>
    //////////////////////////////////////////
    http_server_.route("/static/<arg>", [this, lubuntuci](const QString filename) -> QHttpServerResponse {
        QString sanitized_filename = filename;
        if (filename.contains("..") || filename.contains("../")) {
            return QHttpServerResponse(QHttpServerResponder::StatusCode::BadRequest);
        } else if (filename.startsWith('/')) {
            sanitized_filename = sanitized_filename.remove(0, 1);
        }

        QString staticDir = QDir::currentPath() + "/static";
        QDir dir(staticDir);
        QString fullPath = dir.absoluteFilePath(sanitized_filename);

        QString relativeToStatic = QDir(staticDir).relativeFilePath(fullPath);
        if (relativeToStatic.startsWith("../")) {
            return QHttpServerResponse(QHttpServerResponder::StatusCode::Forbidden);
        }

        QFile file(fullPath);
        if (!file.exists() || !file.open(QIODevice::ReadOnly)) {
            return QHttpServerResponse(QHttpServerResponder::StatusCode::NotFound);
        }
        QByteArray data = file.readAll();
        file.close();

        if (filename.endsWith(".js", Qt::CaseInsensitive)) {
            return QHttpServerResponse("application/javascript", data);
        } else if (filename.endsWith(".css", Qt::CaseInsensitive)) {
            return QHttpServerResponse("text/css", data);
        } else if (filename.endsWith(".html", Qt::CaseInsensitive)
                   || filename.endsWith(".htm", Qt::CaseInsensitive)) {
            return QHttpServerResponse("text/html", data);
        }
        return QHttpServerResponse("application/octet-stream", data);
    });

    //////////////////////////////////////////
    // /graph
    //////////////////////////////////////////
    http_server_.route("/graph", [this, lubuntuci](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
        {
            QHttpServerResponse session_response = verify_session_token(req, req.headers());
            if (session_response.statusCode() == StatusCodeFound) return QtConcurrent::run([response = std::move(session_response)]() mutable { return std::move(response); });
        }
        return QtConcurrent::run([=, this]() {
            std::map<std::string, std::string> scalar_context;
            std::map<std::string, std::vector<std::map<std::string, std::string>>> list_context;
            scalar_context["PAGE_TITLE"] = "Graph - Lubuntu CI";

            const std::string sources_url = "https://ppa.launchpadcontent.net/lubuntu-ci/unstable-ci-proposed/ubuntu/dists/plucky/main/source/Sources.gz";
            const std::string packages_url = "https://ppa.launchpadcontent.net/lubuntu-ci/unstable-ci-proposed/ubuntu/dists/plucky/main/binary-amd64/Packages.gz";

            std::cout << "Downloading and processing Sources.gz...\n";
            auto sourcesOpt = SourcesParser::fetch_and_parse_sources(sources_url);
            if (!sourcesOpt) {
                std::cerr << "Failed to fetch and parse Sources.gz.\n";
            }
            auto sources = *sourcesOpt;

            std::cout << "Downloaded and parsed " << sources.size() << " source packages.\n";

            std::cout << "Downloading and processing Packages.gz (amd64)...\n";
            auto packagesOpt = SourcesParser::fetch_and_parse_packages(packages_url);
            if (!packagesOpt) {
                std::cerr << "Failed to fetch and parse Packages.gz.\n";
            }

            std::cout << "Downloaded and parsed " << packagesOpt->size() << " binary packages.\n";

            auto dependency_graph = SourcesParser::build_dependency_graph(sources, *packagesOpt);
            QString json_output = SourcesParser::serialize_dependency_graph_to_json(dependency_graph);

            scalar_context["GRAPH_JSON"] = json_output.toStdString();

            std::string final_html = TemplateRenderer::render_with_inheritance(
                "graph.html",
                scalar_context,
                list_context
            );

            return QHttpServerResponse("text/html", QByteArray(final_html.c_str(), (int)final_html.size()));
        });
    });

    //////////////////////////////////////////
    // /tasks
    //////////////////////////////////////////
    http_server_.route("/tasks", [this, lubuntuci](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
        {
            QHttpServerResponse session_response = verify_session_token(req, req.headers());
            if (session_response.statusCode() == StatusCodeFound) return QtConcurrent::run([response = std::move(session_response)]() mutable { return std::move(response); });
        }
        // Gather query data
        auto query = req.query();
        std::string type = query.queryItemValue("type").toStdString();
        int page = query.queryItemValue("page").isEmpty() ? 1 : query.queryItemValue("page").toInt();
        int per_page = query.queryItemValue("per_page").isEmpty() ? 30 : query.queryItemValue("per_page").toInt();

        // Return concurrency
        return QtConcurrent::run([=, this]() {
            auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();

            if (!(type.empty() || type == "queued" || type == "complete")) {
                std::string msg = "Invalid type specified.";
                return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
            }

            std::set<std::shared_ptr<Task>, Task::TaskComparator> final_tasks;
            std::string title_prefix;

            static const std::map<std::string, std::shared_ptr<JobStatus>> job_statuses = lubuntuci->cilogic.get_job_statuses();

            if (type.empty()) {
                // default to 'running'
                title_prefix = "Running";
                final_tasks = task_queue->get_running_tasks();
            } else if (type == "queued") {
                title_prefix = "Queued";
                final_tasks = task_queue->get_tasks();
            } else if (type == "complete") {
                title_prefix = "Completed";
                // gather tasks that have start_time > 0 and finish_time > 0
                std::vector<std::shared_ptr<Task>> tasks_vector;
                auto pkgconfs = lubuntuci->cilogic.get_packageconfs();
                for (auto &pkgconf : pkgconfs) {
                    for (auto &j : job_statuses) {
                        if (!j.second) {
                            continue;
                        }
                        auto t = pkgconf->get_task_by_jobstatus(j.second);
                        if (t && t->start_time > 0 && t->finish_time > 0) {
                            tasks_vector.push_back(t);
                        }
                    }
                }
                std::set<std::shared_ptr<Task>, Task::TaskComparator> tasks(
                    tasks_vector.begin(),
                    tasks_vector.end()
                );
                final_tasks = tasks;
            }

            std::map<std::string, std::string> scalar_context = {
                {"PAGE_TITLE", title_prefix + " Tasks"},
                {"PAGE_TYPE", (type.empty() ? "running" : type)}
            };
            std::map<std::string, std::vector<std::map<std::string, std::string>>> list_context;

            std::vector<std::map<std::string, std::string>> tasksVec;
            for (auto task : final_tasks) {
                std::map<std::string, std::string> item;
                item["id"] = std::to_string(task->id);
                item["queued_timestamp"] = std::to_string(task->queue_time);
                item["start_timestamp"] = std::to_string(task->start_time);
                item["finish_timestamp"] = std::to_string(task->finish_time);
                item["running_timedelta"] = std::to_string(now - task->start_time);
                item["score"] = std::to_string(task->jobstatus->build_score);
                item["package_name"] = task->get_parent_packageconf()->package->name;
                item["package_codename"] = task->get_parent_packageconf()->release->codename;
                item["job_status"] = task->jobstatus->display_name;
                item["successful"] = task->successful ? "true" : "false";
                std::string replaced_log = std::regex_replace(task->log->get(), std::regex("\n"), "<br />");
                item["log"] = replaced_log;
                tasksVec.push_back(item);
            }
            list_context["tasks"] = tasksVec;

            std::string final_html = TemplateRenderer::render_with_inheritance(
                "tasks.html",
                scalar_context,
                list_context
            );
            return QHttpServerResponse("text/html", QByteArray(final_html.c_str(), (int)final_html.size()));
        });
    });

    // Attempt to listen on `port`
    if (!tcp_server_.listen(QHostAddress::Any, port) || !http_server_.bind(&tcp_server_)) {
        std::cerr << timestamp_now() << " [ERROR] Could not bind to port " << port << std::endl;
        return false;
    }

    std::cout << timestamp_now() << " [INFO] Web server running on port "
              << tcp_server_.serverPort() << std::endl;
    return true;
}
