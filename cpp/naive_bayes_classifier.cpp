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

#include "naive_bayes_classifier.h"

#include <curl/curl.h>
#include <zlib.h>
#include <algorithm>
#include <cctype>
#include <iostream>
#include <vector>
#include <numeric>
#include <cmath>
#include <cstring>  // for std::memset

/******************************************************************************
 * Constructor / Destructor
 *****************************************************************************/
naive_bayes_classifier::naive_bayes_classifier() = default;
naive_bayes_classifier::~naive_bayes_classifier() = default;

/******************************************************************************
 * reset
 *****************************************************************************/
void naive_bayes_classifier::reset() {
    word_freqs_.clear();
    category_freqs_.clear();
    vocabulary_.clear();
    token_categories_map_.clear();
    total_samples_ = 0.0;
}

/******************************************************************************
 * train_from_url
 *****************************************************************************/
bool naive_bayes_classifier::train_from_url(const std::string &url, const std::string &category) {
    streaming_context ctx;
    ctx.classifier = this;
    ctx.is_prediction_mode = false;
    ctx.category = category;

    bool ok = fetch_and_inflate_gz(url, &naive_bayes_classifier::train_write_cb, &ctx);
    if (!ok) {
        std::cerr << "Error: train_from_url failed for " << url << std::endl;
        return false;
    }
    category_freqs_[category]++;
    total_samples_++;
    return true;
}

/******************************************************************************
 * predict_from_url
 *****************************************************************************/
std::optional<std::string> naive_bayes_classifier::predict_from_url(const std::string &url) const {
    streaming_context ctx;
    ctx.classifier = const_cast<naive_bayes_classifier*>(this);
    ctx.is_prediction_mode = true;

    bool ok = fetch_and_inflate_gz(url, &naive_bayes_classifier::predict_write_cb, &ctx);
    if (!ok) {
        return std::nullopt;
    }
    std::string best_cat = compute_best_category(ctx.prediction_tokens);
    return best_cat;
}

/******************************************************************************
 * prune_common_tokens
 *****************************************************************************/
void naive_bayes_classifier::prune_common_tokens() {
    if (category_freqs_.empty()) {
        return;
    }
    size_t category_count = category_freqs_.size();

    std::vector<std::string> tokens_to_remove_vec;
    tokens_to_remove_vec.reserve(vocabulary_.size());

    for (const auto &[token, cats_set] : token_categories_map_) {
        if (cats_set.size() == category_count) {
            tokens_to_remove_vec.push_back(token);
        }
    }

    for (const auto &tk : tokens_to_remove_vec) {
        vocabulary_.erase(tk);
        for (auto &cat_map : word_freqs_) {
            cat_map.second.erase(tk);
        }
        token_categories_map_.erase(tk);
    }

    std::cout << "Pruned " << tokens_to_remove_vec.size()
              << " common tokens that appeared in all categories.\n";
}

/******************************************************************************
 * train_token
 *****************************************************************************/
void naive_bayes_classifier::train_token(const std::string &category, const std::string &token) {
    if (token.empty()) return;
    word_freqs_[category][token]++;
    vocabulary_[token] = true;
    token_categories_map_[token].insert(category);
}

/******************************************************************************
 * compute_best_category
 *****************************************************************************/
std::string naive_bayes_classifier::compute_best_category(const token_counts_t &tokens) const {
    if (category_freqs_.empty() || total_samples_ <= 0.0) {
        return "Unknown";
    }

    double best_score = -1e308;
    std::string best_cat = "Unknown";

    for (const auto &[cat, cat_count] : category_freqs_) {
        double prior_log = std::log(cat_count / total_samples_);

        double total_cat_words = 0.0;
        auto cat_iter = word_freqs_.find(cat);
        if (cat_iter != word_freqs_.end()) {
            total_cat_words = std::accumulate(
                cat_iter->second.begin(),
                cat_iter->second.end(),
                0.0,
                [](double sum, const auto &p){ return sum + p.second; }
            );
        }

        double score = prior_log;
        for (const auto &[tk, freq] : tokens) {
            double word_count = 0.0;
            if (cat_iter != word_freqs_.end()) {
                auto w_it = cat_iter->second.find(tk);
                if (w_it != cat_iter->second.end()) {
                    word_count = w_it->second;
                }
            }
            double smoothed = (word_count + 1.0) / (total_cat_words + vocabulary_.size());
            score += freq * std::log(smoothed);
        }

        if (score > best_score) {
            best_score = score;
            best_cat = cat;
        }
    }

    return best_cat;
}

/******************************************************************************
 * chunk_to_tokens
 *****************************************************************************/
std::generator<std::string> naive_bayes_classifier::chunk_to_tokens(
    const std::string &chunk, std::string &partial_token)
{
    for (char c : chunk) {
        if (std::isalpha(static_cast<unsigned char>(c))) {
            partial_token.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        } else {
            if (!partial_token.empty()) {
                co_yield partial_token;
                partial_token.clear();
            }
        }
    }
    // leftover partial_token remains if chunk ends mid-token
}

/******************************************************************************
 * train_write_cb
 *****************************************************************************/
size_t naive_bayes_classifier::train_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
    auto ctx = static_cast<streaming_context*>(userdata);
    if (!ctx || !ctx->classifier || ctx->is_prediction_mode) {
        return 0;
    }
    size_t bytes = size * nmemb;
    std::string chunk(ptr, bytes);

    for (auto &&tk : chunk_to_tokens(chunk, ctx->partial_token)) {
        ctx->classifier->train_token(ctx->category, tk);
    }
    return bytes;
}

/******************************************************************************
 * predict_write_cb
 *****************************************************************************/
size_t naive_bayes_classifier::predict_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
    auto ctx = static_cast<streaming_context*>(userdata);
    if (!ctx || !ctx->classifier || !ctx->is_prediction_mode) {
        return 0;
    }
    size_t bytes = size * nmemb;
    std::string chunk(ptr, bytes);

    for (auto &&tk : chunk_to_tokens(chunk, ctx->partial_token)) {
        ctx->prediction_tokens[tk]++;
    }
    return bytes;
}

/******************************************************************************
 * fetch_and_inflate_gz
 *****************************************************************************/
struct inflating_context {
    naive_bayes_classifier::streaming_context *user_ctx;
    size_t (*callback)(char*, size_t, size_t, void*);
    z_stream strm;
    std::string decompress_buffer;

    inflating_context() {
        std::memset(&strm, 0, sizeof(strm));
        strm.zalloc = Z_NULL;
        strm.zfree = Z_NULL;
        strm.opaque = Z_NULL;
        inflateInit2(&strm, 16 + MAX_WBITS);
        decompress_buffer.resize(64 * 1024);
    }

    ~inflating_context() {
        inflateEnd(&strm);
    }
};

static size_t curl_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
    auto *inf_ctx = static_cast<inflating_context*>(userdata);
    size_t total_in = size * nmemb;

    inf_ctx->strm.avail_in = static_cast<uInt>(total_in);
    inf_ctx->strm.next_in  = reinterpret_cast<unsigned char*>(ptr);

    while (inf_ctx->strm.avail_in > 0) {
        inf_ctx->strm.avail_out = static_cast<uInt>(inf_ctx->decompress_buffer.size());
        inf_ctx->strm.next_out  = reinterpret_cast<unsigned char*>(&inf_ctx->decompress_buffer[0]);

        int ret = inflate(&inf_ctx->strm, Z_NO_FLUSH);
        if (ret == Z_STREAM_ERROR || ret == Z_MEM_ERROR || ret == Z_DATA_ERROR) {
            std::cerr << "zlib inflate error: " << inf_ctx->strm.msg << std::endl;
            return 0;
        }

        size_t have = inf_ctx->decompress_buffer.size() - inf_ctx->strm.avail_out;
        if (have > 0) {
            size_t written = inf_ctx->callback(
                &inf_ctx->decompress_buffer[0],
                1,
                have,
                inf_ctx->user_ctx
            );
            if (written < have) {
                return 0;
            }
        }
    }
    return total_in;
}

bool naive_bayes_classifier::fetch_and_inflate_gz(
    const std::string &url,
    size_t (*callback)(char*, size_t, size_t, void*),
    void *user_context)
{
    CURL *curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Error: curl_easy_init failed.\n";
        return false;
    }

    inflating_context inf_ctx;
    inf_ctx.callback = callback;
    inf_ctx.user_ctx = static_cast<streaming_context*>(user_context);

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &inf_ctx);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "cURL error fetching " << url << ": "
                  << curl_easy_strerror(res) << std::endl;
        curl_easy_cleanup(curl);
        return false;
    }
    curl_easy_cleanup(curl);

    auto *ctx = static_cast<streaming_context*>(user_context);
    if (!ctx->partial_token.empty()) {
        if (!ctx->is_prediction_mode) {
            ctx->classifier->train_token(ctx->category, ctx->partial_token);
        } else {
            ctx->prediction_tokens[ctx->partial_token]++;
        }
        ctx->partial_token.clear();
    }
    return true;
}
