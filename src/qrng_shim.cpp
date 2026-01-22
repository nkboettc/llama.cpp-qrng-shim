// common/qrng_shim.cpp  — Buffered AQN QRNG with PRNG fallback
#include "qrng_shim.h"

#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <random>
#include <string>
#include <vector>
#include <algorithm>   // std::min/std::max
#include <chrono>

// Prevent Windows headers from defining min/max macros that break std::min/std::max
#if defined(_WIN32)
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
#endif

#if defined(_WIN32) && !defined(LLAMA_QRNG_HTTP_LIBCURL)
  #define LLAMA_QRNG_HTTP_WINHTTP 1
#endif

#if defined(LLAMA_QRNG_HTTP_WINHTTP)
  #include <windows.h>
  #include <winhttp.h>
  #pragma comment(lib, "winhttp.lib")
#elif defined(LLAMA_QRNG_HTTP_LIBCURL)
  #include <curl/curl.h>
#endif

namespace {

// ---- config knobs (env-overridable) ----
static const char* ENV_API_KEY   = "AQN_API_KEY";
static const char* ENV_API_URL   = "AQN_API_URL"; // e.g. https://api.quantumnumbers.anu.edu.au
static const char* ENV_LOG_JSONL = "LLAMA_QRNG_LOG_JSONL";

struct cfg_t {
    std::string api_key;
    std::string api_url;
    size_t      target_buf = 4096;     // aim to keep this many uint16s buffered
    size_t      batch_len  = 1024;     // per request length (AQN caps at 1024)
    bool        logging    = false;
    std::string log_path;
};

static cfg_t g_cfg;

static std::mt19937                          g_fallback;
static std::uniform_real_distribution<float> g_uni(0.0f, 1.0f);
static std::mutex                            g_mtx;       // guards buffer + fallback RNG
static std::vector<uint16_t>                 g_buf;
static size_t                                g_idx = 0;
static std::atomic<bool>                     g_inited{false};

// lazy-opened log
static std::mutex                            g_log_mtx;
static FILE*                                 g_log = nullptr;

static void log_jsonl_u(float u, bool fallback) {
    if (!g_cfg.logging) return;
    std::lock_guard<std::mutex> lk(g_log_mtx);
    if (!g_log) {
        g_log = std::fopen(g_cfg.log_path.c_str(), "ab");
        if (!g_log) return;
    }
    // minimal, append-only JSON line
    std::fprintf(g_log, "{\"u\":%.9f,\"fallback\":%s}\n", double(u), fallback ? "true" : "false");
    std::fflush(g_log);
}

static std::string getenv_str(const char* k) {
#if defined(_WIN32)
    char* v = nullptr;
    size_t sz = 0;
    if (_dupenv_s(&v, &sz, k) == 0 && v) {
        std::string s(v);
        free(v);
        return s;
    }
    return {};
#else
    const char* v = std::getenv(k);
    return v ? std::string(v) : std::string();
#endif
}

// very small JSON helper: extracts numbers from "data":[ ... ]
static bool parse_uint16_array_from_json(const std::string& js, std::vector<uint16_t>& out) {
    out.clear();
    auto pos = js.find("\"data\"");
    if (pos == std::string::npos) pos = js.find("'data'");
    if (pos == std::string::npos) return false;
    auto lb = js.find('[', pos);
    auto rb = js.find(']', lb == std::string::npos ? 0 : lb + 1);
    if (lb == std::string::npos || rb == std::string::npos || rb <= lb) return false;

    const std::string arr = js.substr(lb + 1, rb - lb - 1);
    size_t i = 0;
    while (i < arr.size()) {
        while (i < arr.size() && (arr[i] <= ' ' || arr[i] == ',')) ++i;
        size_t j = i;
        while (j < arr.size() && std::isdigit(static_cast<unsigned char>(arr[j]))) ++j;
        if (j > i) {
            unsigned long v = std::strtoul(arr.c_str() + i, nullptr, 10);
            if (v <= 65535UL) out.push_back(static_cast<uint16_t>(v));
            i = j;
        } else {
            ++i;
        }
    }
    return !out.empty();
}

#if defined(LLAMA_QRNG_HTTP_WINHTTP)

static std::wstring to_wide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n ? n - 1 : 0, L'\0');
    if (n > 1) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    return w;
}

static bool http_get_json_winhttp(const std::string& url, const std::string& api_key, std::string& out) {
    out.clear();

    HINTERNET hSession = WinHttpOpen(L"Llama-QRNG/1.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    URL_COMPONENTS uc;
    std::memset(&uc, 0, sizeof(uc));
    uc.dwStructSize = sizeof(uc);

    wchar_t host[512] = {0};
    wchar_t path[4096] = {0};
    uc.lpszHostName = host;  uc.dwHostNameLength = sizeof(host)/sizeof(wchar_t);
    uc.lpszUrlPath  = path;  uc.dwUrlPathLength  = sizeof(path)/sizeof(wchar_t);

    std::wstring wurl = to_wide(url);
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &uc)) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::wstring whost(uc.lpszHostName, uc.dwHostNameLength);
    std::wstring wpath(uc.lpszUrlPath,  uc.dwUrlPathLength);

    HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(), uc.nPort, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", wpath.c_str(),
                                            nullptr, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    std::wstring header = L"x-api-key: " + to_wide(api_key);
    WinHttpAddRequestHeaders(hRequest, header.c_str(), (DWORD)-1, WINHTTP_ADDREQ_FLAG_ADD);

    BOOL ok = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                 WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (ok) ok = WinHttpReceiveResponse(hRequest, nullptr);
    if (!ok) {
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return false;
    }

    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) break;
        if (avail == 0) break;
        std::string chunk; chunk.resize(avail);
        DWORD read = 0;
        if (!WinHttpReadData(hRequest, &chunk[0], avail, &read)) break;
        chunk.resize(read);
        out.append(chunk);
        if (read == 0) break;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return !out.empty();
}
#elif defined(LLAMA_QRNG_HTTP_LIBCURL)
static size_t curl_write_cb(char* ptr, size_t sz, size_t nm, void* userdata) {
    auto* s = static_cast<std::string*>(userdata);
    s->append(ptr, sz * nm);
    return sz * nm;
}
static bool http_get_json_curl(const std::string& url, const std::string& api_key, std::string& out) {
    out.clear();
    CURL* c = curl_easy_init();
    if (!c) return false;
    struct curl_slist* hdrs = nullptr;
    std::string key = "x-api-key: " + api_key;
    hdrs = curl_slist_append(hdrs, key.c_str());
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, &curl_write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &out);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);
    CURLcode rc = curl_easy_perform(c);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(c);
    return (rc == CURLE_OK) && !out.empty();
}
#endif

static bool fetch_batch_uint16(size_t want, std::vector<uint16_t>& out) {
    out.clear();

    if (g_cfg.api_key.empty() || g_cfg.api_url.empty()) {
        return false;
    }

    size_t len = std::min<size_t>(g_cfg.batch_len, std::max<size_t>(1, want));

    // Build URL: https://api.quantumnumbers.anu.edu.au?length=LEN&type=uint16
    std::string url = g_cfg.api_url;
    // ensure trailing path is "/" if none
    if (url.find("://") != std::string::npos) {
        // ok
    }
    if (url.back() == '/') url.pop_back();
    url.append("?length=");
    url.append(std::to_string(len));
    url.append("&type=uint16");

    std::string body;
    bool ok = false;
#if defined(LLAMA_QRNG_HTTP_WINHTTP)
    ok = http_get_json_winhttp(url, g_cfg.api_key, body);
#elif defined(LLAMA_QRNG_HTTP_LIBCURL)
    ok = http_get_json_curl(url, g_cfg.api_key, body);
#else
    (void)url;
#endif

    if (!ok) return false;

    std::vector<uint16_t> tmp;
    if (!parse_uint16_array_from_json(body, tmp)) return false;

    out.swap(tmp);
    return true;
}

static void ensure_buffer(size_t min_needed) {
    // called without holding g_mtx
    // try to fill up to target_buf using several requests of up to batch_len
    std::vector<uint16_t> batch;
    while (true) {
        size_t have, cap, need;
{
    std::lock_guard<std::mutex> lk(g_mtx);
    have = (g_buf.size() > g_idx) ? (g_buf.size() - g_idx) : 0;
    cap  = g_cfg.target_buf;

    // Force all arguments to be size_t
if (have >= std::max(min_needed, static_cast<size_t>(1))) return;

size_t needed = std::max(min_needed, static_cast<size_t>(cap));
if (needed < static_cast<size_t>(1)) needed = static_cast<size_t>(1);

need = std::min(
    static_cast<size_t>(g_cfg.batch_len),
    needed - have
);

}

        if (!fetch_batch_uint16(need, batch)) {
            // give up; PRNG fallback will kick in
            return;
        }

        {
            std::lock_guard<std::mutex> lk(g_mtx);
            // append batch to buffer tail; if buffer was fully consumed, reset to compact
            if (g_idx >= g_buf.size()) {
                g_buf.clear();
                g_idx = 0;
            }
            g_buf.insert(g_buf.end(), batch.begin(), batch.end());
        }
    }
}

} // end anonymous namespace

namespace qrng {

void init(uint32_t seed) {
    // configure from env
    g_cfg.api_key  = getenv_str(ENV_API_KEY);
    g_cfg.api_url  = getenv_str(ENV_API_URL);
    g_cfg.log_path = getenv_str(ENV_LOG_JSONL);
    g_cfg.logging  = !g_cfg.log_path.empty();

    {
        std::lock_guard<std::mutex> lk(g_mtx);
        if (seed == 0) seed = std::random_device{}();
        g_fallback.seed(seed);
        g_buf.clear();
        g_idx = 0;
    }

    g_inited.store(true, std::memory_order_relaxed);

    // optional pre-warm
    ensure_buffer(/*min_needed=*/g_cfg.batch_len);
}

float rand01() {
    if (!g_inited.load(std::memory_order_relaxed)) {
        init(0);
    }

    {
        std::lock_guard<std::mutex> lk(g_mtx);
        if (g_idx < g_buf.size()) {
            uint16_t v = g_buf[g_idx++];
            float u = float(v) / 65536.0f;
            log_jsonl_u(u, /*fallback=*/false);
            return u;
        }
    }

    ensure_buffer(/*min_needed=*/1);

    {
        std::lock_guard<std::mutex> lk(g_mtx);
        if (g_idx < g_buf.size()) {
            uint16_t v = g_buf[g_idx++];
            float u = float(v) / 65536.0f;
            log_jsonl_u(u, /*fallback=*/false);
            return u;
        }
    }

    // fallback
    float u = g_uni(g_fallback);
    log_jsonl_u(u, /*fallback=*/true);
    return u;
}

void shutdown() {
    std::lock_guard<std::mutex> lk(g_log_mtx);
    if (g_log) {
        std::fclose(g_log);
        g_log = nullptr;
    }
}

} // namespace qrng
