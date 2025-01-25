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

#ifndef NAIVE_BAYES_CLASSIFIER_H
#define NAIVE_BAYES_CLASSIFIER_H

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <optional>
#include <generator> // C++23 std::generator
#include <cmath>

/******************************************************************************
 * Type aliases
 *****************************************************************************/
using token_counts_t = std::unordered_map<std::string, double>;
using category_counts_t = std::unordered_map<std::string, double>;

/******************************************************************************
 * naive_bayes_classifier
 *
 * A streaming-only Naive Bayes text classifier. It fetches .gz logs via cURL,
 * decompresses them chunk by chunk, tokenizes, and trains or predicts
 * incrementally without storing entire logs in memory.
 *****************************************************************************/
class naive_bayes_classifier {
public:
    naive_bayes_classifier();
    ~naive_bayes_classifier();

    /**************************************************************************
     * train_from_url
     *
     * Streams the .gz log from 'url', decompresses chunk by chunk, extracts
     * tokens, and updates frequency counts for 'category'.
     **************************************************************************/
    bool train_from_url(const std::string &url, const std::string &category);

    /**************************************************************************
     * predict_from_url
     *
     * Streams the .gz log from 'url', decompresses, extracts tokens, and
     * returns the most likely category. Returns std::nullopt if there's an error.
     **************************************************************************/
    std::optional<std::string> predict_from_url(const std::string &url) const;

    /**************************************************************************
     * prune_common_tokens
     *
     * Removes tokens that appear in *all* categories from the vocabulary_
     * and per-category frequencies, reducing noise from universal tokens.
     **************************************************************************/
    void prune_common_tokens();

    /**************************************************************************
     * reset
     *
     * Clears all training data (word_freqs_, category_freqs_, etc.).
     **************************************************************************/
    void reset();

    double total_samples() const { return total_samples_; }
    size_t vocabulary_size() const { return vocabulary_.size(); }

public:
    /**************************************************************************
     * streaming_context
     *
     * Declared *public* so that external structures (like inflating_context)
     * can refer to it. Tracks the current partial token, mode, etc.
     **************************************************************************/
    struct streaming_context {
        naive_bayes_classifier *classifier = nullptr;
        bool is_prediction_mode = false;
        std::string category;    // used if training
        token_counts_t prediction_tokens;
        std::string partial_token;
    };

private:
    /**************************************************************************
     * Data
     **************************************************************************/
    std::unordered_map<std::string, token_counts_t> word_freqs_;  // cat->(word->freq)
    category_counts_t category_freqs_;                            // cat->count of logs
    std::unordered_map<std::string, bool> vocabulary_;            // global set of words
    double total_samples_ = 0.0;

    // For pruning, track which categories each token has appeared in
    std::unordered_map<std::string, std::unordered_set<std::string>> token_categories_map_;

    /**************************************************************************
     * Internal methods
     **************************************************************************/
    void train_token(const std::string &category, const std::string &token);
    std::string compute_best_category(const token_counts_t &tokens) const;

    static std::generator<std::string> chunk_to_tokens(const std::string &chunk,
                                                       std::string &partial_token);

    // Callback for training vs. predicting
    static size_t train_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata);
    static size_t predict_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata);

    // cURL + zlib-based streaming
    static bool fetch_and_inflate_gz(const std::string &url,
                                     size_t (*callback)(char*, size_t, size_t, void*),
                                     void *user_context);
};

#endif // NAIVE_BAYES_CLASSIFIER_H
