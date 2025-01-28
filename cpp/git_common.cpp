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

#include "git_common.h"

#include <fstream>

static int submodule_trampoline(git_submodule* sm, const char* name, void* payload) {
    // Cast payload back to the C++ lambda
    auto* callback = static_cast<std::function<int(git_submodule*, const char*, void*)>*>(payload);
    return (*callback)(sm, name, payload);
}

static int progress_cb(const git_indexer_progress *stats, void *payload) {
    if (stats->total_objects == 0) return 0;

    // Calculate percentage
    int pct = static_cast<int>((static_cast<double>(stats->received_objects) / stats->total_objects) * 100);
    if (pct % 5 == 0) {
        // 0 <= pct <= 100
        if (pct > 100) pct = 100;
        if (pct < 1) pct = 1;
        std::string progress_str = (pct < 10 ? "0" : "") + std::to_string(pct) + "%";

        auto log = static_cast<std::shared_ptr<Log>*>(payload);
        (*log)->append(progress_str);
    }

    return 0;
}

GitCommit get_commit_from_pkg_repo(const std::string& repo_name, std::shared_ptr<Log> log) {
    // Ensure libgit2 is initialized
    ensure_git_inited();

    // Define the repository path
    std::filesystem::path repo_dir = repo_name;

    git_repository* repo = nullptr;
    git_revwalk* walker = nullptr;
    git_commit* commit = nullptr;

    static const std::vector<std::string> COMMIT_SUMMARY_EXCLUSIONS = {
        "GIT_SILENT",
        "SVN_SILENT",
        "Qt Submodule Update Bot",
        "CMake Nightly Date Stamp",
        "https://translate.lxqt-project.org/"
    };

    GitCommit _tmp_commit;
    std::string commit_hash;
    std::string commit_summary;
    std::string commit_message;
    std::chrono::zoned_time<std::chrono::seconds> commit_datetime{
        std::chrono::locate_zone("UTC"),
        std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::time_point{})
    };
    std::string commit_author;
    std::string commit_committer;

    // Attempt to open the repository
    int error = git_repository_open(&repo, repo_dir.c_str());
    if (error != 0) {
        const git_error* e = git_error_last();
        std::string msg = (e && e->message) ? e->message : "unknown error";
        log->append("Failed to open repository: " + msg);
        return GitCommit();
    }

    // Initialize the revwalk
    error = git_revwalk_new(&walker, repo);
    if (error != 0) {
        const git_error* e = git_error_last();
        log->append("Failed to create revwalk: " + std::string(e && e->message ? e->message : "unknown error"));
        git_repository_free(repo);
        return GitCommit();
    }

    // Push HEAD to the walker
    error = git_revwalk_push_head(walker);
    if (error != 0) {
        const git_error* e = git_error_last();
        log->append("Failed to push HEAD to revwalk: " + std::string(e && e->message ? e->message : "unknown error"));
        git_revwalk_free(walker);
        git_repository_free(repo);
        return GitCommit();
    }

    // Optional: Sort commits in topological order and by time
    git_revwalk_sorting(walker, GIT_SORT_TIME | GIT_SORT_TOPOLOGICAL);

    bool found_valid_commit = false;

    // Iterate through commits
    git_oid oid;
    while ((error = git_revwalk_next(&oid, walker)) == 0) {
        // Lookup the commit object using the oid
        error = git_commit_lookup(&commit, repo, &oid);
        if (error != 0) {
            const git_error* e = git_error_last();
            log->append("Failed to lookup commit: " + std::string(e && e->message ? e->message : "unknown error"));
            continue; // Skip to next commit
        }

        // Extract commit summary
        const char* summary_cstr = git_commit_summary(commit);
        if (!summary_cstr) {
            git_commit_free(commit);
            continue; // No summary, skip
        }
        std::string current_summary = summary_cstr;

        // Check if the commit summary contains any exclusion strings
        bool is_excluded = false;
        for (const auto& excl : COMMIT_SUMMARY_EXCLUSIONS) {
            if (current_summary.find(excl) != std::string::npos) {
                is_excluded = true;
                char hash_str[GIT_OID_HEXSZ + 1];
                git_oid_tostr(hash_str, sizeof(hash_str), &oid);
                log->append("Skipping commit " + std::string(hash_str) +
                            " due to exclusion string: \"" + excl + "\"");
                break;
            }
        }

        if (is_excluded) {
            git_commit_free(commit);
            continue; // Skip this commit and move to the next one
        }

        // 1) Extract commit hash
        char hash_str[GIT_OID_HEXSZ + 1];
        git_oid_tostr(hash_str, sizeof(hash_str), &oid);
        commit_hash = hash_str;

        // 2) Extract commit message
        const char* message = git_commit_message(commit);
        if (message) {
            commit_message = message;
        }

        // 3) Extract commit datetime and convert to UTC
        git_time_t c_time = git_commit_time(commit);
        int c_time_offset = git_commit_time_offset(commit); // Offset in minutes from UTC
        std::chrono::system_clock::time_point commit_tp =
            std::chrono::system_clock::from_time_t(static_cast<std::time_t>(c_time));
        std::chrono::minutes offset_minutes(c_time_offset);
        auto utc_time_tp = commit_tp - std::chrono::duration_cast<std::chrono::system_clock::duration>(offset_minutes);
        commit_datetime = std::chrono::zoned_time<std::chrono::seconds>{
            std::chrono::locate_zone("UTC"),
            std::chrono::floor<std::chrono::seconds>(utc_time_tp)
        };

        // 4) Extract commit author
        git_signature* author = nullptr;
        error = git_commit_author_with_mailmap(&author, commit, nullptr);
        if (error == 0 && author) {
            commit_author = std::format("{} <{}>", author->name, author->email);
            git_signature_free(author);
        }

        // 5) Extract commit committer
        git_signature* committer_sig = nullptr;
        error = git_commit_committer_with_mailmap(&committer_sig, commit, nullptr);
        if (error == 0 && committer_sig) {
            commit_committer = std::format("{} <{}>", committer_sig->name, committer_sig->email);
            git_signature_free(committer_sig);
        }

        // Cleanup the commit object
        git_commit_free(commit);
        commit = nullptr;

        // Construct and return the GitCommit object with collected data
        GitCommit git_commit_instance(
            commit_hash,
            current_summary, // Use the current commit summary
            commit_message,
            commit_datetime,
            commit_author,
            commit_committer
        );

        // Check if the commit already exists in the DB
        auto existing_commit = _tmp_commit.get_commit_by_hash(commit_hash);
        if (existing_commit) {
            found_valid_commit = true;
            // Cleanup revwalk and repository before returning
            git_revwalk_free(walker);
            git_repository_free(repo);
            return *existing_commit;
        } else {
            // Insert the new commit into the DB
            found_valid_commit = true;
            // Cleanup revwalk and repository before returning
            git_revwalk_free(walker);
            git_repository_free(repo);
            return git_commit_instance;
        }
    }

    if (error != GIT_ITEROVER && error != 0) {
        const git_error* e = git_error_last();
        log->append("Error during revwalk: " + std::string(e && e->message ? e->message : "unknown error"));
    }

    // Cleanup
    git_revwalk_free(walker);
    git_repository_free(repo);

    if (!found_valid_commit) {
        log->append("No valid commit found without exclusions in repository: " + repo_name);
        return GitCommit();
    }

    // This point should not be reached if a valid commit is found
    return GitCommit();
}

void clone_or_fetch(const std::filesystem::path &repo_dir,
                    const std::string &repo_url,
                    const std::optional<std::string> &branch,
                    std::shared_ptr<Log> log)
{
    ensure_git_inited();

    // Use proxy settings via env var if they exist
    bool proxy = false;
    git_proxy_options proxy_opts = GIT_PROXY_OPTIONS_INIT;
    {
        const char* tmp_proxy = repo_url.rfind("https", 0) == 0 ? std::getenv("HTTPS_PROXY") : std::getenv("HTTP_PROXY");
        if (tmp_proxy) {
            const char* no_proxy_env = std::getenv("NO_PROXY");
            if (no_proxy_env) {
                std::istringstream iss(std::string{no_proxy_env});
                std::string entry;
                bool found_no_proxy = false;
                while (std::getline(iss, entry, ',')) {
                    if (!entry.empty() && repo_url.contains(entry)) {
                        found_no_proxy = true;
                        break;
                    }
                }
                proxy = !found_no_proxy;
            } else {
                proxy = true;
            }

            proxy_opts.type = GIT_PROXY_SPECIFIED;
            proxy_opts.url = tmp_proxy;
        }
    }

    git_repository* repo = nullptr;
    int error = git_repository_open(&repo, repo_dir.c_str());
    if (error == GIT_ENOTFOUND) {
        log->append("Cloning: " + repo_url + " => " + repo_dir.string());
        git_clone_options opts = GIT_CLONE_OPTIONS_INIT;
        if (branch.has_value()) {
            opts.checkout_branch = branch->c_str();
        }

        git_remote_callbacks callbacks = GIT_REMOTE_CALLBACKS_INIT;
        callbacks.transfer_progress = progress_cb;
        callbacks.payload = &log;
        git_fetch_options fetch_opts = GIT_FETCH_OPTIONS_INIT;
        fetch_opts.callbacks = callbacks;
        if (proxy) fetch_opts.proxy_opts = proxy_opts;
        opts.fetch_opts = fetch_opts;

        opts.checkout_opts.checkout_strategy |= GIT_CHECKOUT_UPDATE_SUBMODULES;

        bool success = false;
        for (int attempts = 0; attempts < 5; attempts++) {
            if (git_clone(&repo, repo_url.c_str(), repo_dir.c_str(), &opts) != 0) {
                continue;
            } else {
                success = true;
                break;
            }
        }
        if (!success) {
            const git_error *e = git_error_last();
            throw std::runtime_error("Failed to clone: " +
                                     std::string(e && e->message ? e->message : "unknown"));
        }
        log->append("Repo cloned OK.");
    }
    else if (error == 0) {
        git_remote *remote = nullptr;
        if (git_remote_lookup(&remote, repo, "origin") != 0) {
            const git_error *e = git_error_last();
            git_repository_free(repo);
            throw std::runtime_error("No remote origin: " +
                                     std::string(e && e->message ? e->message : "unknown"));
        }

        git_remote_callbacks callbacks = GIT_REMOTE_CALLBACKS_INIT;
        callbacks.transfer_progress = progress_cb;
        callbacks.payload = &log;
        git_fetch_options fetch_opts = GIT_FETCH_OPTIONS_INIT;
        fetch_opts.callbacks = callbacks;
        if (proxy) fetch_opts.proxy_opts = proxy_opts;

        bool success = false;
        for (int attempts = 0; attempts < 5; attempts++) {
            if (git_remote_fetch(remote, nullptr, &fetch_opts, nullptr) < 0) {
                continue;
            } else {
                success = true;
                break;
            }
        }
        if (!success) {
            const git_error *e = git_error_last();
            git_remote_free(remote);
            git_repository_free(repo);
            throw std::runtime_error("Fetch failed: " +
                                     std::string(e && e->message ? e->message : "unknown"));
        }

        std::string detected_branch = "master";
        git_reference* head_ref = nullptr;
        error = git_reference_lookup(&head_ref, repo, "refs/remotes/origin/HEAD");
        if (error == 0 && head_ref != nullptr) {
            if (git_reference_type(head_ref) & GIT_REFERENCE_SYMBOLIC) {
                const char* symref = git_reference_symbolic_target(head_ref);
                if (symref) {
                    std::string s = symref;
                    std::string prefix = "refs/remotes/origin/";
                    if (s.find(prefix) == 0) {
                        detected_branch = s.substr(prefix.size());
                    }
                }
            }
            git_reference_free(head_ref);
        }

        std::string b = branch.value_or(detected_branch);
        log->append("Using branch: " + b);

        bool successPull = false;
        do {
            std::string localRef  = "refs/heads/" + b;
            std::string remoteRef = "refs/remotes/origin/" + b;

            git_reference* localBranch = nullptr;
            if (git_reference_lookup(&localBranch, repo, localRef.c_str()) == GIT_ENOTFOUND) {
                git_object* remObj = nullptr;
                if (git_revparse_single(&remObj, repo, remoteRef.c_str()) == 0) {
                    git_reference* newB = nullptr;
                    git_branch_create(&newB, repo, b.c_str(), (const git_commit*)remObj, 0);
                    if (newB) git_reference_free(newB);
                    git_object_free(remObj);
                    git_reference_lookup(&localBranch, repo, localRef.c_str());
                }
            }
            if (!localBranch) break;

            git_object* remoteObj = nullptr;
            if (git_revparse_single(&remoteObj, repo, remoteRef.c_str()) < 0) {
                git_reference_free(localBranch);
                break;
            }
            git_oid remoteOid = *git_object_id(remoteObj);

            git_reference* updated = nullptr;
            int ffErr = git_reference_set_target(&updated, localBranch, &remoteOid, "Fast-forward");
            git_reference_free(localBranch);
            git_object_free(remoteObj);
            if (ffErr < 0) {
                if (updated) git_reference_free(updated);
                break;
            }
            {
                git_object* obj = nullptr;
                if (git_revparse_single(&obj, repo, localRef.c_str()) == 0) {
                    git_checkout_options co = GIT_CHECKOUT_OPTIONS_INIT;
                    // Use a more forceful checkout strategy
                    co.checkout_strategy = GIT_CHECKOUT_FORCE | GIT_CHECKOUT_UPDATE_SUBMODULES;
                    if (git_checkout_tree(repo, obj, &co) == 0) {
                        if (git_repository_set_head(repo, localRef.c_str()) == 0) {
                            // Perform a hard reset to ensure working directory and index match HEAD
                            error = git_reset(repo, obj, GIT_RESET_HARD, nullptr);
                            if (error != 0) {
                                const git_error* e = git_error_last();
                                log->append("Failed to reset repository: " + std::string(e && e->message ? e->message : "unknown error"));
                                git_repository_free(repo);
                                throw std::runtime_error("Failed to reset repository after checkout.");
                            }
                            successPull = true;
                        }
                    }
                    git_object_free(obj);
                }
            }
            if (updated) git_reference_free(updated);
        } while(false);

        if (!successPull) {
            std::string bRem = "refs/remotes/origin/" + b;
            git_object* origObj = nullptr;
            if (git_revparse_single(&origObj, repo, bRem.c_str()) == 0) {
                git_reset(repo, origObj, GIT_RESET_HARD, nullptr);
                git_object_free(origObj);

                git_oid newOid;
                if (git_revparse_single(&origObj, repo, bRem.c_str()) == 0) {
                    newOid = *git_object_id(origObj);
                    git_object_free(origObj);
                    std::string lRef = "refs/heads/" + b;
                    git_reference* fRef = nullptr;
                    git_reference_create(&fRef, repo, lRef.c_str(), &newOid, 1,
                                         "Forced local update");
                    if (fRef) git_reference_free(fRef);
                    git_object* co = nullptr;
                    if (git_revparse_single(&co, repo, lRef.c_str()) == 0) {
                        git_checkout_options o = GIT_CHECKOUT_OPTIONS_INIT;
                        o.checkout_strategy = GIT_CHECKOUT_FORCE;
                        if (!git_checkout_tree(repo, co, &o))
                            git_repository_set_head(repo, lRef.c_str());
                        git_object_free(co);
                    }
                }
            }
        }

        std::function<int(git_submodule*, const char*, void*)> submodule_callback;
        submodule_callback = [&](git_submodule* sm, const char* name, void* payload) -> int {
            // Initialize submodule
            if (git_submodule_init(sm, 1) != 0) {
                log->append("Failed to initialize submodule " + std::string(name) + "\n");
                return 0; // Continue with other submodules
            }

            // Set up update options
            git_submodule_update_options opts = GIT_SUBMODULE_UPDATE_OPTIONS_INIT;
            git_remote_callbacks callbacks = GIT_REMOTE_CALLBACKS_INIT;
            callbacks.transfer_progress = progress_cb;
            callbacks.payload = &log;
            opts.version = GIT_SUBMODULE_UPDATE_OPTIONS_VERSION;
            opts.fetch_opts = GIT_FETCH_OPTIONS_INIT;
            opts.fetch_opts.callbacks = callbacks;
            opts.fetch_opts.version = GIT_FETCH_OPTIONS_VERSION;
            if (proxy) opts.fetch_opts.proxy_opts = proxy_opts;
            opts.checkout_opts = GIT_CHECKOUT_OPTIONS_INIT;
            opts.checkout_opts.checkout_strategy = GIT_CHECKOUT_SAFE;

            // Update submodule
            log->append("Updating submodule: " + std::string(name));
            if (git_submodule_update(sm, 1, &opts) != 0) {
                const git_error* e = git_error_last();
                log->append("Failed to update submodule " + std::string(name) + ": " +
                            (e && e->message ? e->message : "unknown"));
            } else {
                log->append("Updated submodule: " + std::string(name));
            }

            // Open the submodule repository
            git_repository* subrepo = nullptr;
            if (git_submodule_open(&subrepo, sm) != 0) {
                log->append("Failed to open submodule repository: " + std::string(name));
                return 0; // Continue with other submodules
            }

            // Recurse into nested submodules
            // Pass the same lambda as the callback by casting it to std::function
            if (git_submodule_foreach(subrepo, submodule_trampoline, &submodule_callback) != 0) {
                const git_error* e = git_error_last();
                log->append("Failed to iterate nested submodules in " + std::string(name) + ": " +
                            (e && e->message ? e->message : "unknown") + "\n");
            }

            git_repository_free(subrepo);
            return 0;
        };

        // Start processing submodules with the top-level repository
        if (git_submodule_foreach(repo, submodule_trampoline, &submodule_callback) != 0) {
            const git_error* e = git_error_last();
            log->append("Failed to iterate over submodules: " +
                        std::string(e && e->message ? e->message : "unknown") + "\n");
        }

        git_remote_free(remote);
        git_repository_free(repo);
    }
}

/**
 * reset_changelog to HEAD content
 */
void reset_changelog(const fs::path &repo_dir, const fs::path &changelog_path) {
    // Remove the .dch path first
    std::remove((std::string{changelog_path.string()} + ".dch").c_str());

    git_repository *repo = nullptr;
    if (git_repository_open(&repo, repo_dir.c_str()) != 0) {
        const git_error *e = git_error_last();
        throw std::runtime_error(std::string("reset_changelog: open failed: ")
                                 + (e && e->message ? e->message : "???"));
    }
    git_reference *head_ref = nullptr;
    if (git_repository_head(&head_ref, repo) != 0) {
        const git_error *e = git_error_last();
        git_repository_free(repo);
        throw std::runtime_error(std::string("reset_changelog: repository_head: ")
                                 + (e && e->message ? e->message : "???"));
    }
    git_commit *commit = nullptr;
    if (git_reference_peel((git_object**)&commit, head_ref, GIT_OBJECT_COMMIT) != 0) {
        const git_error *e = git_error_last();
        git_reference_free(head_ref);
        git_repository_free(repo);
        throw std::runtime_error(std::string("reset_changelog: peel HEAD: ")
                                 + (e && e->message ? e->message : "???"));
    }
    git_tree *tree = nullptr;
    if (git_commit_tree(&tree, commit) != 0) {
        const git_error *e = git_error_last();
        git_commit_free(commit);
        git_reference_free(head_ref);
        git_repository_free(repo);
        throw std::runtime_error(std::string("reset_changelog: commit_tree: ")
                                 + (e && e->message ? e->message : "???"));
    }
    std::error_code ec;
    auto rel_path = fs::relative(changelog_path, repo_dir, ec);
    if (ec) {
        git_tree_free(tree);
        git_commit_free(commit);
        git_reference_free(head_ref);
        git_repository_free(repo);
        throw std::runtime_error("reset_changelog: relative path error: " + ec.message());
    }
    git_tree_entry *entry = nullptr;
    if (git_tree_entry_bypath(&entry, tree, rel_path.string().c_str()) != 0) {
        git_tree_free(tree);
        git_commit_free(commit);
        git_reference_free(head_ref);
        git_repository_free(repo);
        throw std::runtime_error("reset_changelog: cannot find debian/changelog in HEAD");
    }
    git_blob *blob = nullptr;
    if (git_tree_entry_to_object((git_object**)&blob, repo, entry) != 0) {
        git_tree_entry_free(entry);
        git_tree_free(tree);
        git_commit_free(commit);
        git_reference_free(head_ref);
        git_repository_free(repo);
        const git_error *e = git_error_last();
        throw std::runtime_error(std::string("reset_changelog: cannot get blob: ")
                                 + (e && e->message ? e->message : "???"));
    }
    const char *content = (const char*)git_blob_rawcontent(blob);
    size_t sz = git_blob_rawsize(blob);
    {
        std::ofstream out(changelog_path, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            git_blob_free(blob);
            git_tree_entry_free(entry);
            git_tree_free(tree);
            git_commit_free(commit);
            git_reference_free(head_ref);
            git_repository_free(repo);
            throw std::runtime_error("reset_changelog: cannot open " + changelog_path.string());
        }
        out.write(content, sz);
    }
    git_blob_free(blob);
    git_tree_entry_free(entry);
    git_tree_free(tree);
    git_commit_free(commit);
    git_reference_free(head_ref);
    git_repository_free(repo);
}
