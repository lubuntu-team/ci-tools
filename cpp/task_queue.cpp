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

#include "task_queue.h"
#include <iostream>
#include <QSqlError>

TaskQueue::TaskQueue(size_t max_concurrent_tasks)
    : max_concurrent_tasks_(max_concurrent_tasks), stop_(false),
      tasks_(),
      running_tasks_() {}

TaskQueue::~TaskQueue() {
    stop();
}

// FIXME: copy of CiLogic::get_thread_connection()
std::atomic<unsigned int> TaskQueue::thread_id_counter{1200};
QSqlDatabase TaskQueue::get_thread_connection() {
    std::lock_guard<std::mutex> lock(connection_mutex_);
    thread_local unsigned int thread_unique_id = thread_id_counter.fetch_add(1);
    QString connectionName = QString("LubuntuCIConnection_%1").arg(thread_unique_id);

    // Check if the connection already exists for this thread
    if (QSqlDatabase::contains(connectionName)) {
        QSqlDatabase db = QSqlDatabase::database(connectionName);
        if (!db.isOpen()) {
            if (!db.open()) {
                throw std::runtime_error("Failed to open thread-specific database connection: " + db.lastError().text().toStdString());
            }
        }
        return db;
    }

    QSqlDatabase threadDb = QSqlDatabase::addDatabase("QSQLITE", connectionName);
    threadDb.setDatabaseName("/srv/lubuntu-ci/repos/ci-tools/lubuntu_ci.db");

    if (!threadDb.open()) {
        throw std::runtime_error("Failed to open new database connection for thread: " + threadDb.lastError().text().toStdString());
    }

    return threadDb;
}

void TaskQueue::enqueue(std::shared_ptr<JobStatus> jobstatus,
                        std::function<void(std::shared_ptr<Log> log)> task_func,
                        std::shared_ptr<PackageConf> packageconf) {
    {
        auto connection = get_thread_connection();
        auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();

        // Create the task
        std::shared_ptr<Task> task_ptr = std::make_shared<Task>(connection, jobstatus, now, packageconf);
        task_ptr->func = [task_func, self_weak = std::weak_ptr<Task>(task_ptr)](std::shared_ptr<Log> log) {
            std::shared_ptr<Task> task_locked = self_weak.lock();
            if (task_locked) {
                log->assign_task_context(task_locked);
                task_func(log);
            }
        };
        packageconf->assign_task(jobstatus, task_ptr, packageconf);

        std::unique_lock<std::mutex> lock(tasks_mutex_);
        tasks_.emplace(task_ptr);
    }
    cv_.notify_all(); // Notify worker threads
}

void TaskQueue::start() {
    stop_ = false;
    for (size_t i = 0; i < max_concurrent_tasks_; ++i) {
        workers_.emplace_back(&TaskQueue::worker_thread, this);
    }
}

void TaskQueue::stop() {
   {
        std::unique_lock<std::mutex> tasks_lock(tasks_mutex_);
        std::unique_lock<std::mutex> pkgconfs_lock(running_pkgconfs_mutex_);
        std::unique_lock<std::mutex> running_tasks_lock(running_tasks_mutex_);
        stop_ = true;
    }
    cv_.notify_all(); // Wake up all threads
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

std::set<std::shared_ptr<Task>, Task::TaskComparator> TaskQueue::get_tasks() const {
    std::lock_guard<std::mutex> lock(tasks_mutex_);
    return tasks_;
}

std::set<std::shared_ptr<Task>, Task::TaskComparator> TaskQueue::get_running_tasks() const {
    std::lock_guard<std::mutex> lock(running_tasks_mutex_);
    return running_tasks_;
}

void TaskQueue::worker_thread() {
    int worker_id = max_worker_id++;
    while (true) {
        std::shared_ptr<Task> task_to_execute;
        {
            std::lock_guard<std::mutex> tasks_lock(tasks_mutex_);

            if (stop_ && tasks_.empty()) {
                return; // Exit thread if stopping and no tasks left
            }

            auto it = tasks_.begin();
            bool found_valid = false;
            // Iterate through the set until a valid task is found
            while (it != tasks_.end()) {
                std::lock_guard<std::mutex> lock(running_pkgconfs_mutex_);
                std::shared_ptr<Task> it_task = *it;
                task_to_execute = it_task;

                int pkgconf_id = task_to_execute->get_parent_packageconf()->id;
                auto running_pkgconf_it = std::find_if(running_pkgconfs_.begin(), running_pkgconfs_.end(),
                    [&pkgconf_id](const std::shared_ptr<PackageConf>& pkgconf) { return pkgconf->id == pkgconf_id; });

                if (running_pkgconf_it != running_pkgconfs_.end()) {
                    ++it; // Move to the next task
                    continue;
                }

                // Task is valid to execute
                found_valid = true;
                it = tasks_.erase(it);
                break;
            }
            if (!found_valid) { continue; }
        }

        if (!task_to_execute || !task_to_execute->func) {
            continue;
        } else {
            std::lock_guard<std::mutex> pkgconfslock(running_pkgconfs_mutex_);
            running_pkgconfs_.insert(task_to_execute->get_parent_packageconf());
            std::lock_guard<std::mutex> tasks_lock(running_tasks_mutex_);
            running_tasks_.insert(task_to_execute);
        }

        // Set the start time
        {
            auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
            task_to_execute->start_time = now;
            auto connection = get_thread_connection();
            task_to_execute->save(connection, 0);
        }

        try {
            task_to_execute->func(task_to_execute->log); // Execute the task
            task_to_execute->successful = true;
        } catch (const std::exception& e) {
            task_to_execute->successful = false;
            std::ostringstream oss;
            oss << "Exception type: " << typeid(e).name() << "\n"
                << "What: " << e.what();
            task_to_execute->log->append(oss.str());
        } catch (...) {
            task_to_execute->successful = false;
            task_to_execute->log->append("Unknown exception occurred");
        }

        {
            auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch())
                      .count();
            task_to_execute->finish_time = now;
            auto connection = get_thread_connection();
            task_to_execute->save(connection, 0);
        }

        {
            // Remove the task from running_tasks_
            std::lock_guard<std::mutex> lock(running_tasks_mutex_);
            int id = task_to_execute->id;
            auto running_task_it = std::find_if(running_tasks_.begin(), running_tasks_.end(),
                [&id](const std::shared_ptr<Task>& task) { return task->id == id; });

            if (running_task_it != running_tasks_.end()) {
                running_tasks_.erase(running_task_it);
            }
        }

        {
            // Remove packageconf from running_pkgconfs_ by id
            std::lock_guard<std::mutex> lock(running_pkgconfs_mutex_);
            int pkgconf_id = task_to_execute->get_parent_packageconf()->id;
            auto running_pkgconf_it = std::find_if(running_pkgconfs_.begin(), running_pkgconfs_.end(),
                [&pkgconf_id](const std::shared_ptr<PackageConf>& pkgconf) { return pkgconf->id == pkgconf_id; });

            if (running_pkgconf_it != running_pkgconfs_.end()) {
                running_pkgconfs_.erase(running_pkgconf_it);
            }
        }
    }
}
