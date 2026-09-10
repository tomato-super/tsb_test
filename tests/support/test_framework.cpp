#include "test_framework.hpp"

#include <iostream>

namespace tsb_test {

void ReportFailure(const char* file, int line, const std::string& msg) {
    std::cout << "    " << file << ":" << line << ": " << msg << "\n";
}

namespace {
std::string RenderU128(unsigned __int128 v) {
    if (v == 0) return "0";
    std::string s;
    while (v > 0) {
        s.push_back(static_cast<char>('0' + static_cast<int>(v % 10)));
        v /= 10;
    }
    std::reverse(s.begin(), s.end());
    return s;
}
}  // namespace

std::string RenderValue(unsigned __int128 v) { return RenderU128(v); }

std::string RenderValue(__int128 v) {
    if (v < 0) return "-" + RenderU128(static_cast<unsigned __int128>(-v));
    return RenderU128(static_cast<unsigned __int128>(v));
}

std::string RenderBytes(const uint8_t* data, size_t n) {
    std::string s = "0x";
    for (size_t i = 0; i < n; ++i) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", data[i]);
        s += buf;
    }
    return s;
}

std::string RenderEscaped(const std::string& s) {
    std::string out = "\"";
    for (unsigned char c : s) {
        if (c == '"') {
            out += "\\\"";
        } else if (c == '\\') {
            out += "\\\\";
        } else if (c == '\n') {
            out += "\\n";
        } else if (c == '\t') {
            out += "\\t";
        } else if (c >= 0x20 && c < 0x7f) {
            out += static_cast<char>(c);
        } else {
            char buf[8];
            std::snprintf(buf, sizeof(buf), "\\x%02x", c);
            out += buf;
        }
    }
    out += "\"";
    return out;
}

int RunAll(const char* filter) {
    int passed = 0;
    int failed = 0;
    int skipped = 0;

    for (const auto& tc : registry()) {
        const std::string full = tc.suite + "." + tc.name;
        if (filter != nullptr && full.find(filter) == std::string::npos) {
            ++skipped;
            continue;
        }

        current_failures() = 0;
        std::cout << "[ RUN      ] " << full << "\n";
        try {
            tc.fn();
        } catch (const std::exception& e) {
            ++current_failures();
            std::cout << "    抛出未捕获异常: " << e.what() << "\n";
        } catch (...) {
            ++current_failures();
            std::cout << "    抛出未知类型的未捕获异常\n";
        }

        if (current_failures() == 0) {
            ++passed;
            std::cout << "[       OK ] " << full << "\n";
        } else {
            ++failed;
            std::cout << "[  FAILED  ] " << full << " (" << current_failures()
                      << " 处断言失败)\n";
        }
    }

    std::cout << "\n========================================\n";
    std::cout << "通过: " << passed << "  失败: " << failed;
    if (skipped > 0) std::cout << "  跳过: " << skipped;
    std::cout << "\n";
    std::cout << "========================================\n";

    return failed == 0 ? 0 : 1;
}

}  // namespace tsb_test
