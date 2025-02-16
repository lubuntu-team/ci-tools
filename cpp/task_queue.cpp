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

void TaskQueue::enqueue(std::shared_ptr<JobStatus> jobstatus,
                        std::function<void(std::shared_ptr<Log> log)> task_func,
                        std::shared_ptr<PackageConf> packageconf) {
    {
        auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                       .count();
        std::shared_ptr<Task> task_ptr = std::make_shared<Task>(jobstatus, now, packageconf);
        task_ptr->func = [task_func, self_weak = std::weak_ptr<Task>(task_ptr)](std::shared_ptr<Log> log) mutable {
            if (auto task_locked = self_weak.lock())
                task_func(log);
        };
        if (jobstatus->name != "system") packageconf->assign_task(jobstatus, task_ptr, packageconf);

        std::unique_lock<std::mutex> lock(tasks_mutex_);
        tasks_.emplace(task_ptr);
    }
    cv_.notify_all();
}

void TaskQueue::start() {
    stop_ = false;
    for (size_t i = 0; i < max_concurrent_tasks_; ++i) {
        workers_.emplace_back(&TaskQueue::worker_thread, this);
    }
}

void TaskQueue::stop() {
    {
        std::unique_lock<std::mutex> lock(tasks_mutex_);
        stop_ = true;
    }
    cv_.notify_all();
    for (auto &worker : workers_) {
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
            std::unique_lock<std::mutex> lock(tasks_mutex_);
            cv_.wait(lock, [this] { return stop_ || !tasks_.empty(); });
            if (stop_ && tasks_.empty()) return;
            auto it = tasks_.begin();
            while (it != tasks_.end()) {
                if (!(*it)->get_parent_packageconf()) {
                    task_to_execute = *it;
                    tasks_.erase(it);
                    break;
                }
                int package_id = (*it)->get_parent_packageconf()->package->id;
                {
                    std::lock_guard<std::mutex> pkg_lock(running_packages_mutex_);
                    auto running_it = std::find_if(running_packages_.begin(), running_packages_.end(),
                        [package_id](const std::shared_ptr<Package> &pkg) { return pkg->id == package_id; });
                    if (running_it != running_packages_.end()) {
                        ++it;
                        continue;
                    }
                }
                task_to_execute = *it;
                tasks_.erase(it);
                break;
            }
        }
        if (!task_to_execute || !task_to_execute->func) continue;
        else if (task_to_execute->get_parent_packageconf()) {
            std::lock_guard<std::mutex> pkg_lock(running_packages_mutex_);
            running_packages_.insert(task_to_execute->get_parent_packageconf()->package);
        }
        {
            std::lock_guard<std::mutex> rt_lock(running_tasks_mutex_);
            running_tasks_.insert(task_to_execute);
        }
        auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::system_clock::now().time_since_epoch()).count();
        task_to_execute->start_time = now;
        try {
            task_to_execute->func(task_to_execute->log);
            task_to_execute->successful = true;
        } catch (const std::exception &e) {
            task_to_execute->successful = false;
            std::ostringstream oss;
            oss << "Exception type: " << typeid(e).name() << "\n"
                << "What: " << e.what();
            task_to_execute->log->append(oss.str());
        } catch (...) {
            task_to_execute->successful = false;
            task_to_execute->log->append("Unknown exception occurred");
        }
        now = std::chrono::duration_cast<std::chrono::milliseconds>(
                  std::chrono::system_clock::now().time_since_epoch()).count();
        task_to_execute->finish_time = now;
        {
            std::lock_guard<std::mutex> rt_lock(running_tasks_mutex_);
            int id = task_to_execute->id;
            auto it = std::find_if(running_tasks_.begin(), running_tasks_.end(),
                [id](const std::shared_ptr<Task> &task) { return task->id == id; });
            if (it != running_tasks_.end()) {
                running_tasks_.erase(it);
            }
        }
        if (task_to_execute->get_parent_packageconf()) {
            std::lock_guard<std::mutex> pkg_lock(running_packages_mutex_);
            int package_id = task_to_execute->get_parent_packageconf()->package->id;
            auto it = std::find_if(running_packages_.begin(), running_packages_.end(),
                [package_id](const std::shared_ptr<Package> &pkg) { return pkg->id == package_id; });
            if (it != running_packages_.end()) {
                running_packages_.erase(it);
            }
        }
        task_to_execute->save(0);
    }
}
