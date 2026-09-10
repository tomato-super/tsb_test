#pragma once

// 最小依赖的测试框架（不引入 gtest/catch2，避免外部依赖与网络获取）
//
// 用法：
//   #include "test_framework.hpp"
//   TEST(SuiteName, CaseName) {
//       EXPECT_EQ(compute(), expected);
//       EXPECT_TRUE(cond);
//   }
//   TSB_TEST_MAIN()
//
// 断言失败会记录并继续执行；每个用例结束时若失败数 > 0 则标记为失败。

#include <array>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <functional>
#include <stdexcept>
#include <sstream>
#include <string>
#include <vector>

namespace tsb_test {

struct TestCase {
    std::string suite;
    std::string name;
    std::function<void()> fn;
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> r;
    return r;
}

// 每个用例开始时重置
inline int& current_failures() {
    static int n = 0;
    return n;
}

struct Registrar {
    Registrar(const char* suite, const char* name, std::function<void()> fn) {
        registry().push_back({suite, name, std::move(fn)});
    }
};

// 供断言宏使用的失败上报
void ReportFailure(const char* file, int line, const std::string& msg);

// 渲染任意可流式输出的值；对 uint128_t 等类型提供专门重载
template <typename T>
std::string Render(const T& v) {
    std::ostringstream oss;
    oss << v;
    return oss.str();
}

std::string RenderValue(unsigned __int128 v);
std::string RenderValue(__int128 v);
std::string RenderBytes(const uint8_t* data, size_t n);

// 字符串按可读形式渲染，非打印字节转义，避免污染终端
std::string RenderEscaped(const std::string& s);
inline std::string RenderValue(const std::string& s) { return RenderEscaped(s); }
inline std::string RenderValue(const char* s) {
    return RenderEscaped(std::string(s == nullptr ? "(null)" : s));
}

// 字节容器渲染为十六进制，便于比较密钥与密文块
template <size_t N>
std::string RenderValue(const std::array<uint8_t, N>& v) {
    return RenderBytes(v.data(), v.size());
}
inline std::string RenderValue(const std::vector<uint8_t>& v) {
    return RenderBytes(v.data(), v.size());
}

// 其余类型走 Render<T> 的流式输出
template <typename T>
std::string RenderValue(const T& v) {
    return Render(v);
}

int RunAll(const char* filter);

// 致命断言失败时抛出，由 RunAll 捕获并记为失败
struct AssertionFailed : std::runtime_error {
    explicit AssertionFailed(const std::string& m) : std::runtime_error(m) {}
};

}  // namespace tsb_test

#define TSB_TEST_CONCAT_(a, b) a##b
#define TSB_TEST_CONCAT(a, b) TSB_TEST_CONCAT_(a, b)

#define TEST(suite, name)                                                      \
    static void TSB_TEST_CONCAT(tsb_test_fn_, __LINE__)();                     \
    static ::tsb_test::Registrar TSB_TEST_CONCAT(tsb_test_reg_, __LINE__)(     \
        #suite, #name, &TSB_TEST_CONCAT(tsb_test_fn_, __LINE__));              \
    static void TSB_TEST_CONCAT(tsb_test_fn_, __LINE__)()

#define TSB_FAIL_(msg)                                                         \
    do {                                                                       \
        ++::tsb_test::current_failures();                                      \
        ::tsb_test::ReportFailure(__FILE__, __LINE__, (msg));                  \
    } while (0)

#define EXPECT_TRUE(expr)                                                      \
    do {                                                                       \
        if (!(expr)) {                                                         \
            TSB_FAIL_("EXPECT_TRUE(" #expr ") 失败");                           \
        }                                                                      \
    } while (0)

#define EXPECT_FALSE(expr)                                                     \
    do {                                                                       \
        if ((expr)) {                                                          \
            TSB_FAIL_("EXPECT_FALSE(" #expr ") 失败");                          \
        }                                                                      \
    } while (0)

#define EXPECT_EQ(lhs, rhs)                                                    \
    do {                                                                       \
        const auto& _l = (lhs);                                                \
        const auto& _r = (rhs);                                                \
        if (!(_l == _r)) {                                                     \
            TSB_FAIL_(std::string("EXPECT_EQ(" #lhs ", " #rhs ") 失败: 实际=") \
                      + ::tsb_test::RenderValue(_l) + " 期望="                 \
                      + ::tsb_test::RenderValue(_r));                          \
        }                                                                      \
    } while (0)

#define EXPECT_NE(lhs, rhs)                                                    \
    do {                                                                       \
        const auto& _l = (lhs);                                                \
        const auto& _r = (rhs);                                                \
        if ((_l == _r)) {                                                      \
            TSB_FAIL_(std::string("EXPECT_NE(" #lhs ", " #rhs ") 失败: 两边都是=") \
                      + ::tsb_test::RenderValue(_l));                          \
        }                                                                      \
    } while (0)

#define TSB_ABORT_(msg)                                                        \
    do {                                                                       \
        ++::tsb_test::current_failures();                                      \
        ::tsb_test::ReportFailure(__FILE__, __LINE__, (msg));                  \
        throw ::tsb_test::AssertionFailed(msg);                                \
    } while (0)

#define ASSERT_TRUE(expr)                                                      \
    do {                                                                       \
        if (!(expr)) {                                                         \
            TSB_ABORT_("ASSERT_TRUE(" #expr ") 失败");                          \
        }                                                                      \
    } while (0)

#define ASSERT_EQ(lhs, rhs)                                                    \
    do {                                                                       \
        const auto& _l = (lhs);                                                \
        const auto& _r = (rhs);                                                \
        if (!(_l == _r)) {                                                     \
            TSB_ABORT_(std::string("ASSERT_EQ(" #lhs ", " #rhs ") 失败: 实际=") \
                       + ::tsb_test::RenderValue(_l) + " 期望="                \
                       + ::tsb_test::RenderValue(_r));                         \
        }                                                                      \
    } while (0)

// 断言不抛异常
#define EXPECT_NO_THROW(expr)                                                  \
    do {                                                                       \
        try {                                                                  \
            (void)(expr);                                                      \
        } catch (const std::exception& _e) {                                   \
            TSB_FAIL_(std::string("EXPECT_NO_THROW(" #expr ") 抛出了异常: ") +  \
                      _e.what());                                              \
        } catch (...) {                                                        \
            TSB_FAIL_("EXPECT_NO_THROW(" #expr ") 抛出了未知异常");             \
        }                                                                      \
    } while (0)

// 断言抛异常
#define EXPECT_THROW(expr, exception_type)                                     \
    do {                                                                       \
        bool _thrown = false;                                                  \
        try {                                                                  \
            (void)(expr);                                                      \
        } catch (const exception_type&) {                                      \
            _thrown = true;                                                    \
        } catch (...) {                                                        \
            TSB_FAIL_("EXPECT_THROW(" #expr ") 抛出了类型不匹配的异常");        \
            _thrown = true;                                                    \
        }                                                                      \
        if (!_thrown) {                                                        \
            TSB_FAIL_("EXPECT_THROW(" #expr ") 未抛出异常");                    \
        }                                                                      \
    } while (0)

// 用例主入口。放在单独的定义单元（test_framework_main.cpp）里，
// 这样每个测试可执行文件都能注册自己的用例集而不冲突。
#define TSB_TEST_MAIN()                                                        \
    int main(int argc, char** argv) {                                          \
        const char* filter = argc > 1 ? argv[1] : nullptr;                     \
        return ::tsb_test::RunAll(filter);                                     \
    }
