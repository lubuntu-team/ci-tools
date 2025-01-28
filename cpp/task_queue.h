// Copyright (C) 2025 Simon Quigley <tsimonq2@ubuntu.com>
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

#ifndef TASK_QUEUE_H
#define TASK_QUEUE_H

#include "ci_database_objs.h"

#include <set>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <string>
#include <queue>

#include <QSqlDatabase>

class TaskQueue {
public:
    TaskQueue(size_t max_concurrent_tasks = 10);
    ~TaskQueue();

    void enqueue(std::shared_ptr<JobStatus> jobstatus, std::function<void(std::shared_ptr<Log> log)> task_func, std::shared_ptr<PackageConf> packageconf);
    void start();
    void stop();

    std::set<std::shared_ptr<Task>, Task::TaskComparator> get_tasks() const;
    std::set<std::shared_ptr<Task>, Task::TaskComparator> get_running_tasks() const;

private:
    size_t max_concurrent_tasks_;
    std::set<std::shared_ptr<Task>, Task::TaskComparator> tasks_;
    std::set<std::shared_ptr<Task>, Task::TaskComparator> running_tasks_;
    std::set<std::shared_ptr<Package>> running_packages_;
    std::queue<std::function<void()>> thread_pool_tasks_;
    mutable std::mutex tasks_mutex_;
    mutable std::mutex running_packages_mutex_;
    mutable std::mutex running_tasks_mutex_;
    std::condition_variable cv_;
    bool stop_;
    std::vector<std::thread> workers_;
    int max_worker_id = 1;

    void worker_thread();
};

#endif // TASK_QUEUE_H
