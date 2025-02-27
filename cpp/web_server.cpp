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
#include "db_common.h"
#include "template_renderer.h"
#include "ci_logic.h"

// Qt includes
#include <QtHttpServer/QHttpServer>
#include <QtHttpServer/QHttpServerRequest>
#include <QtHttpServer/QHttpServerResponse>
#include <QSslServer>
#include <QDir>
#include <QFile>
#include <QDateTime>
#include <QJsonArray>
#include <QDebug>
#include <QtConcurrent/QtConcurrent>
#include <QFile>
#include <QFuture>
#include <QSqlQuery>
#include <QSqlError>
#include <QSslKey>

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
    // Validate token length
    if (token.size() != 64) return false;

    // If there are no active tokens, validation fails
    if (_active_tokens.isEmpty()) return false;

    // Check if the token exists in the active tokens map
    auto it = _active_tokens.find(token);
    if (it != _active_tokens.end()) {
        // Check if the token is not expired
        if (it.value() >= QDateTime::currentDateTime()) return true;

        // Token is expired, erase it safely
        _active_tokens.erase(it);

        // Also remove the token from the person map, if it exists
        auto person_it = _token_person.find(token);
        if (person_it != _token_person.end()) _token_person.erase(person_it);

        return false;
    }

    // Token not found
    return false;
}

[[nodiscard]] QHttpServerResponse WebServer::verify_session_token(const QHttpServerRequest &request, const QHttpHeaders &headers) {
    const QUrl request_url = request.url();
    const QString current_path = request_url.path();
    auto get = [&](const char* name) -> QString {
        QByteArray val = headers.value(name).toByteArray();
        return val.isEmpty() ? QString() : QString::fromUtf8(val);
    };

    const QString scheme = get("X-Forwarded-Proto").isEmpty() ? request_url.scheme() : get("X-Forwarded-Proto");
    const QString host = get("X-Forwarded-Host").isEmpty() ? request_url.host() : get("X-Forwarded-Host");
    int port = get("X-Forwarded-Port").isEmpty() ? request.url().port() : get("X-Forwarded-Port").toInt();
    QString base_url = scheme + "://" + host;
    if (port != -1 && port != 80 && port != 443) base_url += ":" + QString::number(port);

    for (const auto &cookie : headers.value(QHttpHeaders::WellKnownHeader::Cookie).toByteArray().split(';')
                            | std::views::transform([](const QByteArray &cookie) { return cookie.trimmed(); })
                            | std::views::filter([](const QByteArray &cookie) { return cookie.startsWith("auth_token="); })) {
        if (!validate_token(QString::fromUtf8(cookie.mid(sizeof("auth_token=") - 1)))) break;
        return QHttpServerResponse(QHttpServerResponder::StatusCode::Ok);
    }

    QHttpServerResponse bad_response(StatusCodeFound);
    QHttpHeaders bad_response_headers;
    bad_response_headers.replaceOrAppend(QHttpHeaders::WellKnownHeader::Location,
                                          "/unauthorized?base_url=" + base_url + "&redirect_to=" + current_path);
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

    // Use our new list_known_repos() method from CiLogic
    std::shared_ptr<CiLogic> cilogic = std::make_shared<CiLogic>();
    std::vector<std::shared_ptr<PackageConf>> all_repos = cilogic->list_known_repos();
    task_queue = std::make_unique<TaskQueue>(6);
    std::shared_ptr<std::map<std::string, std::shared_ptr<JobStatus>>> job_statuses = cilogic->get_job_statuses();
    task_queue->start();

    // Load initial tokens from the database
    {
        QSqlQuery load_tokens(get_thread_connection());
        load_tokens.prepare("SELECT person.id, person.username, person.logo_url, person_token.token, person_token.expiry_date FROM person INNER JOIN person_token ON person.id = person_token.person_id");
        ci_query_exec(&load_tokens);
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

    expire_tokens_thread_ = std::jthread(run_task_every, 60, [this, cilogic] {
        QSqlQuery expired_tokens(get_thread_connection());
        QString current_time = QDateTime::currentDateTime().toString(Qt::ISODate);

        expired_tokens.prepare("DELETE FROM person_token WHERE expiry_date < :current_time");
        expired_tokens.bindValue(":current_time", current_time);
        ci_query_exec(&expired_tokens);
        for (auto it = _active_tokens.begin(); it != _active_tokens.end();) {
            if (it.value() <= QDateTime::currentDateTime()) it = _active_tokens.erase(it);
            else ++it;
        }
        for (auto it = _token_person.begin(); it != _token_person.end();) {
            if (!_active_tokens.contains(it.key())) it = _token_person.erase(it);
            else ++it;
        }
    });

    process_sources_thread_ = std::jthread(run_task_every, 10, [this, all_repos, proposed, cilogic, job_statuses] {
        std::shared_ptr<PackageConf> null_pkgconf;
        task_queue->enqueue(
            job_statuses->at("system"),
            [this, all_repos, proposed, job_statuses](std::shared_ptr<Log> log) mutable {
                for (auto pkgconf : all_repos) {
                    if (!pkgconf->can_check_source_upload()) continue;
                    std::string package_version = pkgconf->upstream_version + "-0ubuntu0~ppa" + std::to_string(pkgconf->ppa_revision);
                    log->append(std::format("Enqueueing build check for {}/{}", pkgconf->package->name, package_version));
                    task_queue->enqueue(
                        job_statuses->at("source_check"),
                        [this, package_version, pkgconf, proposed](std::shared_ptr<Log> log) mutable {
                            pkgconf->sync();
                            bool found_in_ppa = false;
                            for (auto spph : proposed.getPublishedSources("", "", std::nullopt, true, true, "", pkgconf->package->name, "", package_version)) {
                                found_in_ppa = true;
                                log->append(std::format("{}/{} found", pkgconf->package->name, package_version));
                                break;
                            }
                            if (!found_in_ppa) throw std::runtime_error("Not found in the PPA.");
                        },
                        pkgconf
                    );
                }
            },
            null_pkgconf
        );
    });

    process_binaries_thread_ = std::jthread(run_task_every, 15, [this, all_repos, proposed, cilogic, job_statuses] {
        std::shared_ptr<PackageConf> null_pkgconf;
        task_queue->enqueue(
            job_statuses->at("system"),
            [this, all_repos, job_statuses, proposed](std::shared_ptr<Log> log) mutable {
                for (auto pkgconf : all_repos) {
                    if (!pkgconf->can_check_builds()) continue;
                    std::string package_version = pkgconf->upstream_version + "-0ubuntu0~ppa" + std::to_string(pkgconf->ppa_revision);
                    log->append(std::format("Enqueueing build check for {}/{}", pkgconf->package->name, package_version));
                    task_queue->enqueue(
                        job_statuses->at("build_check"),
                        [this, proposed, pkgconf, package_version](std::shared_ptr<Log> log) mutable {
                            pkgconf->sync();
                            bool found_in_ppa = false;
                            source_package_publishing_history target_spph;
                            for (auto spph : proposed.getPublishedSources("", "", std::nullopt, true, true, "", pkgconf->package->name, "", package_version)) {
                                found_in_ppa = true;
                                target_spph = spph;
                                break;
                            }

                            if (!found_in_ppa) throw std::runtime_error("Not found in the PPA.");

                            bool all_builds_passed = true;
                            for (auto build : target_spph.getBuilds()) {
                                if (build.buildstate != "Successfully built") all_builds_passed = false;
                                log->append(std::format("Build of {} {} in {} for {} has a status of {}",
                                                        pkgconf->package->name, package_version, pkgconf->release->codename,
                                                        build.arch_tag, build.buildstate));
                            }

                            if (!all_builds_passed) throw std::runtime_error("Build(s) pending or failed, job is not successful.");

                        },
                        pkgconf
                    );
                }
            },
            null_pkgconf
        );
    });

    ////////////////////////////////////////////////////////////////
    // /unauthorized?base_url=<base_url>&redirect_to=<redirect_to>
    ////////////////////////////////////////////////////////////////
    http_server_.route("/unauthorized", [this, cilogic](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
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
    http_server_.route("/authcallback", [this, cilogic](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
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
                QSqlQuery get_person(get_thread_connection());
                get_person.prepare("SELECT id, username, logo_url FROM person WHERE username = ?");
                get_person.bindValue(0, QString::fromStdString(username));
                if (!ci_query_exec(&get_person)) { qDebug() << "Error executing SELECT query for person:" << get_person.lastError(); }

                if (get_person.next()) {
                    person = Person(get_person.value(0).toInt(), get_person.value(1).toString().toStdString(),
                                    get_person.value(2).toString().toStdString());
                } else {
                    QSqlQuery insert_person(get_thread_connection());
                    insert_person.prepare("INSERT INTO person (username, logo_url) VALUES (?, ?)");
                    insert_person.bindValue(0, QString::fromStdString(username));
                    insert_person.bindValue(1, QString::fromStdString("https://api.launchpad.net/devel/~" + username + "/logo"));
                    if (!ci_query_exec(&insert_person)) { qDebug() << "Error executing INSERT query for person:" << insert_person.lastError(); }

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
                QSqlQuery insert_token(get_thread_connection());
                insert_token.prepare("INSERT INTO person_token (person_id, token, expiry_date) VALUES (?, ?, ?)");
                insert_token.bindValue(0, person.id);
                insert_token.bindValue(1, token);
                insert_token.bindValue(2, one_day.toString(Qt::ISODate));
                if (!ci_query_exec(&insert_token)) { qDebug() << "Error executing INSERT query for token:" << insert_token.lastError(); }
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
    http_server_.route("/", [this, cilogic, job_statuses](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
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
            auto all_repos = cilogic->list_known_repos();
            int total_size = static_cast<int>(all_repos.size());
            int total_pages = (per_page > 0)
                              ? (total_size + per_page - 1) / per_page
                              : 1;

            auto repos = cilogic->list_known_repos(page, per_page, sort_by, sort_order);
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
                    if (commit_summary.size() > 40)
                        commit_summary = commit_summary.substr(0, 37) + "...";
                    packaging_commit_str = r->packaging_commit->commit_hash.substr(0, 7) +
                        std::format(" ({:%Y-%m-%d %H:%M:%S %Z})<br />", r->packaging_commit->commit_datetime) +
                        commit_summary;
                }
                if (r->upstream_commit) {
                    std::string commit_summary = r->upstream_commit->commit_summary;
                    if (commit_summary.size() > 40)
                        commit_summary = commit_summary.substr(0, 37) + "...";
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

                for (auto const & [job_name, job_ptr] : *job_statuses) {
                    auto t = r->get_task_by_jobstatus(job_ptr);
                    if (t) {
                        std::string css_class = "bg-secondary";

                        if (t->finish_time > 0) {
                            css_class = t->successful ? "bg-success" : "bg-danger";
                        } else if (t->start_time > 0) {
                            css_class = "bg-warning";
                        } else {
                            css_class = "bg-info";
                        }

                        item[job_name + "_class"] = css_class;
                        item[job_name + "_id"] = std::to_string(t->id);
                    } else {
                        item[job_name + "_class"] = "";
                        item[job_name + "_id"] = "";
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
    http_server_.route("/pull", [this, cilogic, job_statuses](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
        {
            QHttpServerResponse session_response = verify_session_token(req, req.headers());
            if (session_response.statusCode() == StatusCodeFound) return QtConcurrent::run([response = std::move(session_response)]() mutable { return std::move(response); });
        }
        auto query = req.query();
        QString repo_string = query.queryItemValue("repo");

        return QtConcurrent::run([=, this]() {
            if (repo_string.isEmpty() || !repo_string.toInt(nullptr, 10)) {
                std::string msg = "No valid repo specified.";
                return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
            }
            int repo = std::stoi(repo_string.toStdString());

            std::string msg = cilogic->queue_pull_tarball({ cilogic->get_packageconf_by_id(repo) }, task_queue, job_statuses);
            return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
        });
    });

    //////////////////////////////////////////
    // /build?repo=<id>
    //////////////////////////////////////////
    http_server_.route("/build", [this, cilogic, job_statuses](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
        {
            QHttpServerResponse session_response = verify_session_token(req, req.headers());
            if (session_response.statusCode() == StatusCodeFound) return QtConcurrent::run([response = std::move(session_response)]() mutable { return std::move(response); });
        }
        auto query = req.query();
        QString repo_string = query.queryItemValue("repo");

        return QtConcurrent::run([=, this]() {
            if (repo_string.isEmpty() || !repo_string.toInt(nullptr, 10)) {
                std::string msg = "No valid repo specified.";
                return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
            }
            int repo = std::stoi(repo_string.toStdString());

            std::string msg = cilogic->queue_build_upload({ cilogic->get_packageconf_by_id(repo) }, task_queue, job_statuses);
            return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
        });
    });

    //////////////////////////////////////////
    // /pull-selected?repos=<ids>
    //////////////////////////////////////////
    http_server_.route("/pull-selected", [this, cilogic, job_statuses](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
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

            std::string msg = cilogic->queue_pull_tarball(cilogic->get_packageconfs_by_ids(repos), task_queue, job_statuses);
            return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
        });
    });

    //////////////////////////////////////////
    // /build-selected?repos=foo,bar,baz
    //////////////////////////////////////////
    http_server_.route("/build-selected", [this, cilogic, job_statuses](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
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

            std::string msg = cilogic->queue_build_upload(cilogic->get_packageconfs_by_ids(repos), task_queue, job_statuses);
            return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
        });
    });

    //////////////////////////////////////////
    // /pull-and-build-selected?repos=foo,bar,baz
    //////////////////////////////////////////
    http_server_.route("/pull-and-build-selected", [this, cilogic, job_statuses](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
        {
            QHttpServerResponse session_response = verify_session_token(req, req.headers());
            if (session_response.statusCode() == StatusCodeFound) return QtConcurrent::run([response = std::move(session_response)]() mutable { return std::move(response); });
        }
        auto query = req.query();
        std::string repos_str = query.queryItemValue("repos").toStdString();

        return QtConcurrent::run([=, this]() {
            if (repos_str.empty()) {
                std::string msg = "<div class='text-danger'>No repositories specified for pull and build.</div>";
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
            auto pkgconfs = cilogic->get_packageconfs_by_ids(repos);
            for (auto pkgconf : pkgconfs) pkgconf->clear_tasks();

            std::string msg = cilogic->queue_pull_tarball(pkgconfs, task_queue, job_statuses);
            msg += cilogic->queue_build_upload(pkgconfs, task_queue, job_statuses);
            return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
        });
    });

    //////////////////////////////////////////
    // /pull-all
    //////////////////////////////////////////
    http_server_.route("/pull-all", [this, cilogic, all_repos, job_statuses](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
        {
            QHttpServerResponse session_response = verify_session_token(req, req.headers());
            if (session_response.statusCode() == StatusCodeFound) return QtConcurrent::run([response = std::move(session_response)]() mutable { return std::move(response); });
        }
        return QtConcurrent::run([=, this]() {
            std::string msg = cilogic->queue_pull_tarball(all_repos, task_queue, job_statuses);

            return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
        });
    });

    //////////////////////////////////////////
    // /build-all
    //////////////////////////////////////////
    http_server_.route("/build-all", [this, cilogic, all_repos, job_statuses](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
        {
            QHttpServerResponse session_response = verify_session_token(req, req.headers());
            if (session_response.statusCode() == StatusCodeFound) return QtConcurrent::run([response = std::move(session_response)]() mutable { return std::move(response); });
        }
        return QtConcurrent::run([=, this]() {
            std::string msg = cilogic->queue_build_upload(all_repos, task_queue, job_statuses);

            return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
        });
    });

    //////////////////////////////////////////
    // /pull-and-build-all
    //////////////////////////////////////////
    http_server_.route("/pull-and-build-all", [this, cilogic, all_repos, job_statuses](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
        {
            QHttpServerResponse session_response = verify_session_token(req, req.headers());
            if (session_response.statusCode() == StatusCodeFound) return QtConcurrent::run([response = std::move(session_response)]() mutable { return std::move(response); });
        }
        return QtConcurrent::run([=, this]() {
            for (auto pkgconf : all_repos) pkgconf->clear_tasks();
            std::string msg = cilogic->queue_pull_tarball(all_repos, task_queue, job_statuses);
            msg += cilogic->queue_build_upload(all_repos, task_queue, job_statuses);

            return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
        });
    });

    //////////////////////////////////////////
    // Serve static files from /static/<arg>
    //////////////////////////////////////////
    http_server_.route("/static/<arg>", [this, cilogic, job_statuses](const QString filename) -> QHttpServerResponse {
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
    http_server_.route("/graph", [this, cilogic, job_statuses](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
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
    http_server_.route("/tasks", [this, cilogic, job_statuses](const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
        {
            QHttpServerResponse session_response = verify_session_token(req, req.headers());
            if (session_response.statusCode() == StatusCodeFound) return QtConcurrent::run([response = std::move(session_response)]() mutable { return std::move(response); });
        }
        // Gather query data
        auto query = req.query();
        std::string type = query.queryItemValue("type").toStdString();
        int page = query.queryItemValue("page").isEmpty() ? 1 : query.queryItemValue("page").toInt();
        int per_page = query.queryItemValue("per_page").isEmpty() ? 30 : query.queryItemValue("per_page").toInt();

        return QtConcurrent::run([=, this]() {
            if (!(type.empty() || type == "queued" || type == "complete")) {
                std::string msg = "Invalid type specified.";
                return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
            }

            std::set<std::shared_ptr<Task>, Task::TaskComparator> final_tasks;
            std::string title_prefix;

            if (type.empty()) {
                title_prefix = "Running";
                final_tasks = task_queue->get_running_tasks();
            } else if (type == "queued") {
                title_prefix = "Queued";
                final_tasks = task_queue->get_tasks();
            } else if (type == "complete") {
                title_prefix = "Completed";
                std::vector<std::shared_ptr<Task>> tasks_vector;
                for (auto &pkgconf : cilogic->get_packageconfs()) {
                    for (auto &j : *job_statuses) {
                        if (!j.second) continue;
                        auto t = pkgconf->get_task_by_jobstatus(j.second);
                        if (t && t->start_time > 0 && t->finish_time > 0) tasks_vector.push_back(t);
                    }
                }
                std::set<std::shared_ptr<Task>, Task::TaskComparator> tasks(tasks_vector.begin(), tasks_vector.end());
                final_tasks = tasks;
            }

            std::map<std::string, std::vector<std::map<std::string, std::string>>> list_context;

            {
                auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
                std::vector<std::map<std::string, std::string>> tasks_vec;
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
                    tasks_vec.push_back(item);
                }
                list_context["tasks"] = tasks_vec;
            }

            std::map<std::string, std::string> scalar_context = {
                {"PAGE_TITLE", title_prefix + " Tasks"},
                {"PAGE_TYPE", (type.empty() ? "running" : type)}
            };
            std::string final_html = TemplateRenderer::render_with_inheritance("tasks.html", scalar_context, list_context);
            return QHttpServerResponse("text/html", QByteArray(final_html.c_str(), (int)final_html.size()));
        });
    });

    //////////////////////////////////////////
    // /log/<TASK_ID>
    //////////////////////////////////////////
    http_server_.route("/log/<arg>", [this, cilogic, job_statuses](const QString _task_id, const QHttpServerRequest &req) -> QFuture<QHttpServerResponse> {
        {
            QHttpServerResponse session_response = verify_session_token(req, req.headers());
            if (session_response.statusCode() == StatusCodeFound) return QtConcurrent::run([response = std::move(session_response)]() mutable { return std::move(response); });
        }
        return QtConcurrent::run([=, this]() {
            int task_id;
            try {
                task_id = _task_id.toInt();
                if (task_id <= 0) {
                    std::string msg = "<html><body><h1>Invalid task ID specified.</h1></body></html>";
                    return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
                }
            } catch (...) {
                std::string msg = "<html><body><h1>Invalid task ID specified.</h1></body></html>";
                return QHttpServerResponse("text/html", QByteArray(msg.c_str(), (int)msg.size()));
            }
            std::string log_content = cilogic->get_task_log(task_id);
            std::map<std::string, std::string> context;
            std::map<std::string, std::vector<std::map<std::string, std::string>>> list_context;
            context["title"] = "Task Logs";
            context["log"] = log_content;
            std::string final_html = TemplateRenderer::render_with_inheritance("log.html", context, list_context);
            return QHttpServerResponse("text/html", QByteArray(final_html.c_str(), (int)final_html.size()));
        });
    });

    {
        QSslConfiguration ssl_config = QSslConfiguration::defaultConfiguration();
        QFile cert_file("/srv/lubuntu-ci/repos/ci-tools/server.crt");
        cert_file.open(QIODevice::ReadOnly);
        ssl_config.setLocalCertificate(QSslCertificate(&cert_file, QSsl::Pem));
        cert_file.close();
        QFile key_file("/srv/lubuntu-ci/repos/ci-tools/server.key");
        key_file.open(QIODevice::ReadOnly);
        ssl_config.setPrivateKey(QSslKey(&key_file, QSsl::Rsa, QSsl::Pem));
        key_file.close();
        ssl_config.setPeerVerifyMode(QSslSocket::VerifyNone);
        ssl_config.setProtocol(QSsl::TlsV1_3);
        ssl_server_.setSslConfiguration(ssl_config);

        QHttp2Configuration Http2Conf = QHttp2Configuration();
        Http2Conf.setServerPushEnabled(true);
        http_server_.setHttp2Configuration(Http2Conf);
    }

    if (!ssl_server_.listen(QHostAddress::Any, port) || !http_server_.bind(&ssl_server_)) {
        std::cerr << timestamp_now() << " [ERROR] Could not bind to port " << port << std::endl;
        return false;
    }

    std::cout << timestamp_now() << " [INFO] Web server running on port "
              << ssl_server_.serverPort() << std::endl;
    return true;
}
