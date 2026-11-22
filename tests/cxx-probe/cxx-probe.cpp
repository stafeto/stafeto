// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// The C++ runtime on relibc (libc++, libc++abi and libunwind of
// tools/build-libcxx.py), as one static program. Every check prints its own
// line with the value it computed, and xtask cxx-probe compares the lines.
// A check that fails prints "cxx-probe: check failed at line N" and ends the
// program with exit code 10.
#include <atomic>
#include <barrier>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <exception>
#include <future>
#include <iomanip>
#include <iostream>
#include <latch>
#include <locale>
#include <memory>
#include <mutex>
#include <semaphore>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <typeinfo>
#include <vector>

#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define CHECK(cond)                                                                      \
    do {                                                                                 \
        if (!(cond)) {                                                                   \
            std::printf("cxx-probe: check failed at line %d: %s (errno %d)\n", __LINE__, #cond, errno); \
            std::fflush(stdout);                                                         \
            std::_Exit(10);                                                              \
        }                                                                                \
    } while (0)

static void say(const char *what) { std::printf("cxx-probe: %s\n", what); }

// ---- static constructors and destructors, atexit --------------------------
// Constructed before main, destroyed at exit in the reverse order of their
// construction together with the atexit handlers registered between them.

// The copy that init starts has no code the layer could copy for a fork, so it
// starts the file /bin/cxx-probe with the argument "run" and waits for it; only
// that copy checks and prints the lines of its destructors.
static bool running_checks = false;
static int constructed_before_main = 0;
static int order_of_construction = 0;

struct Static {
    const char *name;
    int seq;
    explicit Static(const char *n) : name(n), seq(++order_of_construction) {
        constructed_before_main += 1;
    }
    ~Static() {
        if (running_checks)
            std::printf("cxx-probe: static destructor %s (constructed %d)\n", name, seq);
    }
};

static Static first_static("first");
static Static second_static("second");
static std::string static_string = std::string("a static string") + " of the library";

static void at_exit_one() {
    if (running_checks) say("atexit handler one");
}
static void at_exit_two() {
    if (running_checks) say("atexit handler two");
}

// A thread_local of the main thread, destroyed at exit through
// __cxa_thread_atexit_impl.
struct Tls {
    std::atomic<int> *counter;
    int value;
    Tls() : counter(nullptr), value(0) {}
    ~Tls() {
        if (counter) counter->fetch_add(1);
    }
};

static thread_local Tls tls_object;
static thread_local int tls_plain = 7;
static std::atomic<int> tls_destroyed{0};

static std::thread::id main_thread;

struct MainTls {
    ~MainTls() {
        if (running_checks && std::this_thread::get_id() == main_thread)
            std::printf("cxx-probe: main thread_local destructor ran\n");
    }
};
static thread_local MainTls main_tls;

// ---- exceptions -----------------------------------------------------------

static std::atomic<int> raii_live{0};
static int raii_destroyed = 0;

struct Raii {
    Raii() { raii_live.fetch_add(1); }
    ~Raii() {
        raii_live.fetch_sub(1);
        raii_destroyed += 1;
    }
};

struct MyError : std::runtime_error {
    int code;
    MyError(const char *w, int c) : std::runtime_error(w), code(c) {}
};

[[gnu::noinline]] static int deep(int depth, int code) {
    Raii guard;
    if (depth == 0) throw MyError("from the fifth frame", code);
    volatile int sink = depth;
    int r = deep(depth - 1, code);
    return r + sink;
}

static int compare_throwing(const void *a, const void *b, void *arg) {
    int *calls = static_cast<int *>(arg);
    *calls += 1;
    Raii guard;
    if (*calls == 3) throw MyError("from a comparison function", 77);
    return *static_cast<const int *>(a) - *static_cast<const int *>(b);
}

[[gnu::noinline]] static void sort_that_throws(int *calls) {
    int data[8] = {5, 3, 8, 1, 9, 2, 7, 4};
    qsort_r(data, 8, sizeof(int), compare_throwing, calls);
}

static void check_exceptions() {
    // Through five frames, with the destructors of the frames running.
    int result = 0;
    int code = 0;
    const char *what = "";
    try {
        result = deep(5, 42);
    } catch (const MyError &e) {
        code = e.code;
        what = e.what();
    }
    CHECK(result == 0);
    CHECK(raii_live.load() == 0);
    std::printf("cxx-probe: exception through 5 frames: %s code %d, %d destructors ran\n", what,
                code, raii_destroyed);
    CHECK(code == 42 && raii_destroyed == 6);

    // Caught by a base class, by a catch-all, and rethrown.
    try {
        try {
            throw MyError("inner", 1);
        } catch (const std::exception &e) {
            std::printf("cxx-probe: caught as std::exception: %s\n", e.what());
            throw;
        }
    } catch (const MyError &e) {
        std::printf("cxx-probe: rethrown and caught as MyError: code %d\n", e.code);
        CHECK(e.code == 1);
    }
    try {
        throw 17;
    } catch (...) {
        say("catch-all caught an int");
    }

    // Through a frame that is not C++: relibc's qsort_r calls the comparison
    // function, which throws.
    int calls = 0;
    int caught = 0;
    try {
        sort_that_throws(&calls);
    } catch (const MyError &e) {
        caught = e.code;
    }
    std::printf("cxx-probe: exception through qsort_r: code %d after %d comparisons\n", caught,
                calls);
    CHECK(caught == 77 && calls == 3);

    // The exception object travels: exception_ptr and a nested exception.
    std::exception_ptr saved;
    try {
        throw std::out_of_range("held in an exception_ptr");
    } catch (...) {
        saved = std::current_exception();
    }
    try {
        std::rethrow_exception(saved);
    } catch (const std::out_of_range &e) {
        std::printf("cxx-probe: exception_ptr rethrown: %s\n", e.what());
    }
    try {
        try {
            throw std::runtime_error("cause");
        } catch (...) {
            std::throw_with_nested(std::logic_error("effect"));
        }
    } catch (const std::logic_error &e) {
        try {
            std::rethrow_if_nested(e);
        } catch (const std::runtime_error &cause) {
            std::printf("cxx-probe: nested exception: %s because %s\n", e.what(), cause.what());
        }
    }

    // The allocator's failure is an exception.
    bool bad_alloc = false;
    try {
        volatile std::size_t huge = static_cast<std::size_t>(-1) / 4;
        char *p = new char[huge];
        p[0] = 1;
        delete[] p;
    } catch (const std::bad_alloc &) {
        bad_alloc = true;
    }
    std::printf("cxx-probe: new of a huge size throws bad_alloc: %d\n", bad_alloc ? 1 : 0);
    CHECK(bad_alloc);
}

// ---- run-time type information --------------------------------------------

struct Shape {
    virtual ~Shape() = default;
    virtual const char *name() const { return "shape"; }
};
struct Round : virtual Shape {
    const char *name() const override { return "round"; }
};
struct Flat : virtual Shape {
    const char *name() const override { return "flat"; }
};
struct Disc : Round, Flat {
    const char *name() const override { return "disc"; }
};
struct Other {
    virtual ~Other() = default;
};

static void check_rtti() {
    Disc disc;
    Shape *shape = &disc;
    Round *round = dynamic_cast<Round *>(shape);
    Flat *flat = dynamic_cast<Flat *>(round);  // a cross cast
    Disc *down = dynamic_cast<Disc *>(shape);
    Other *other = dynamic_cast<Other *>(shape);
    std::printf("cxx-probe: dynamic_cast up %d cross %d down %d unrelated %d\n", round != nullptr,
                flat != nullptr, down == &disc, other != nullptr);
    CHECK(round && flat && down == &disc && !other);
    void *whole = dynamic_cast<void *>(shape);
    CHECK(whole == static_cast<void *>(&disc));
    bool bad_cast = false;
    try {
        Other &o = dynamic_cast<Other &>(*shape);
        (void)o;
    } catch (const std::bad_cast &) {
        bad_cast = true;
    }
    CHECK(bad_cast);
    Shape plain;
    CHECK(dynamic_cast<Disc *>(&plain) == nullptr);
    std::printf("cxx-probe: typeid of a Shape* to a Disc: %s equal %d, a Shape: equal %d, bad_cast %d\n",
                shape->name(), typeid(*shape) == typeid(Disc), typeid(plain) == typeid(Shape),
                bad_cast ? 1 : 0);
    CHECK(typeid(*shape) == typeid(Disc) && typeid(*shape) != typeid(Shape));
    std::printf("cxx-probe: type names: %s %s\n", typeid(int).name(), typeid(Disc).name());
    CHECK(std::strcmp(typeid(int).name(), "i") == 0);
}

// ---- threads --------------------------------------------------------------

static std::atomic<int> sum_of_threads{0};

static void check_threads() {
    // Four threads and a mutex.
    std::mutex lock;
    long total = 0;
    std::vector<std::thread> threads;
    for (int i = 1; i <= 4; i++) {
        threads.emplace_back([&lock, &total, i] {
            for (int k = 0; k < 100; k++) {
                std::lock_guard<std::mutex> hold(lock);
                total += i;
            }
        });
    }
    for (auto &t : threads) t.join();
    std::printf("cxx-probe: 4 threads with a mutex: total %ld\n", total);
    CHECK(total == 1000);

    // An exception thrown and caught inside a thread; one handed to the joiner
    // through a promise.
    std::promise<int> promise;
    std::future<int> future = promise.get_future();
    std::thread t([&promise] {
        try {
            throw MyError("inside a thread", 9);
        } catch (const MyError &e) {
            promise.set_exception(std::make_exception_ptr(e));
        }
    });
    int from_thread = 0;
    try {
        (void)future.get();
    } catch (const MyError &e) {
        from_thread = e.code;
    }
    t.join();
    std::printf("cxx-probe: exception handed from a thread through a promise: code %d\n",
                from_thread);
    CHECK(from_thread == 9);

    // async and a future with a value.
    auto answer = std::async(std::launch::async, [] { return 6 * 7; });
    std::printf("cxx-probe: std::async result %d\n", answer.get());

    // Condition variable with a deadline: a timeout, then a wake.
    std::mutex m;
    std::condition_variable cv;
    bool ready = false;
    auto before = std::chrono::steady_clock::now();
    {
        std::unique_lock<std::mutex> hold(m);
        std::cv_status status = cv.wait_for(hold, std::chrono::milliseconds(40));
        auto waited = std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::steady_clock::now() - before)
                          .count();
        std::printf("cxx-probe: condition_variable wait_for timeout %d after at least 40 ms %d\n",
                    status == std::cv_status::timeout, waited >= 40);
        CHECK(status == std::cv_status::timeout && waited >= 40);
    }
    std::thread waker([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        {
            std::lock_guard<std::mutex> hold(m);
            ready = true;
        }
        cv.notify_one();
    });
    {
        std::unique_lock<std::mutex> hold(m);
        bool woken = cv.wait_for(hold, std::chrono::seconds(20), [&] { return ready; });
        std::printf("cxx-probe: condition_variable notified before the deadline: %d\n",
                    woken ? 1 : 0);
        CHECK(woken);
    }
    waker.join();

    // thread_local objects with destructors: each thread's destructor runs as
    // the thread ends, before join returns.
    tls_destroyed = 0;
    std::vector<std::thread> workers;
    for (int i = 0; i < 3; i++) {
        workers.emplace_back([i] {
            tls_object.counter = &tls_destroyed;
            tls_object.value = i + 1;
            tls_plain += i;
            sum_of_threads.fetch_add(tls_plain);
        });
    }
    for (auto &w : workers) w.join();
    std::printf("cxx-probe: thread_local destructors after 3 threads: %d, their plain values %d\n",
                tls_destroyed.load(), sum_of_threads.load());
    CHECK(tls_destroyed.load() == 3 && sum_of_threads.load() == 7 * 3 + 0 + 1 + 2);
    CHECK(tls_plain == 7);
    // Use it, so that the main thread has the destructor registered: exit
    // runs it before the destructors of the static objects.
    MainTls *registered = &main_tls;
    CHECK(registered != nullptr);
}

// ---- waits by address -----------------------------------------------------

static void check_atomic_wait() {
    std::atomic<int> flag{0};
    std::atomic<int> state{0};
    std::thread waiter([&] {
        flag.wait(0);          // sleeps while the value is 0
        state.store(flag.load() * 10);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    CHECK(state.load() == 0);  // still asleep
    flag.store(4);
    flag.notify_one();
    waiter.join();
    std::printf("cxx-probe: std::atomic::wait woken by notify_one: %d\n", state.load());
    CHECK(state.load() == 40);

    std::latch latch(3);
    std::atomic<int> through{0};
    std::vector<std::thread> arrivals;
    for (int i = 0; i < 3; i++) {
        arrivals.emplace_back([&] {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            latch.count_down();
            latch.wait();
            through.fetch_add(1);
        });
    }
    for (auto &t : arrivals) t.join();
    std::printf("cxx-probe: std::latch released %d threads\n", through.load());
    CHECK(through.load() == 3);

    std::barrier sync(3);
    std::atomic<int> phases{0};
    std::vector<std::thread> crew;
    for (int i = 0; i < 3; i++) {
        crew.emplace_back([&] {
            for (int round = 0; round < 5; round++) {
                sync.arrive_and_wait();
                phases.fetch_add(1);
            }
        });
    }
    for (auto &t : crew) t.join();
    std::printf("cxx-probe: std::barrier 5 rounds of 3 threads: %d\n", phases.load());
    CHECK(phases.load() == 15);

    std::counting_semaphore<4> semaphore(0);
    std::thread giver([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        semaphore.release(2);
    });
    bool got = semaphore.try_acquire_for(std::chrono::seconds(20));
    bool second = semaphore.try_acquire_for(std::chrono::seconds(20));
    bool third = semaphore.try_acquire_for(std::chrono::milliseconds(30));
    giver.join();
    std::printf("cxx-probe: counting_semaphore acquired %d %d, a third timed out %d\n", got, second,
                third ? 0 : 1);
    CHECK(got && second && !third);
}

// ---- iostreams and locales ------------------------------------------------

struct Grouping : std::numpunct<char> {
    char do_thousands_sep() const override { return '\''; }
    std::string do_grouping() const override { return "\3"; }
};

static void check_streams_and_locales() {
    std::cout << "cxx-probe: iostream cout " << 42 << ' ' << 2.5 << ' ' << std::hex << 255
              << std::dec << ' ' << std::boolalpha << true << std::endl;
    std::ostringstream out;
    out << std::fixed << std::setprecision(3) << 3.14159 << ' ' << -7 << ' ' << "text";
    std::printf("cxx-probe: ostringstream: %s\n", out.str().c_str());
    CHECK(out.str() == "3.142 -7 text");
    std::istringstream in("12 3.5 word");
    int i = 0;
    double d = 0;
    std::string w;
    in >> i >> d >> w;
    std::printf("cxx-probe: istringstream: %d %g %s\n", i, d, w.c_str());
    CHECK(i == 12 && d == 3.5 && w == "word");
    std::cerr << "cxx-probe: iostream cerr line" << std::endl;

    std::locale classic = std::locale::classic();
    CHECK(classic.name() == "C");
    const std::ctype<char> &ctype = std::use_facet<std::ctype<char>>(classic);
    std::printf("cxx-probe: locale C: isalpha(a) %d isdigit(a) %d toupper(q) %c ispunct(!) %d isspace(tab) %d\n",
                ctype.is(std::ctype_base::alpha, 'a'), ctype.is(std::ctype_base::digit, 'a'),
                ctype.toupper('q'), ctype.is(std::ctype_base::punct, '!'),
                ctype.is(std::ctype_base::space, '\t'));
    CHECK(ctype.is(std::ctype_base::alpha, 'a') && !ctype.is(std::ctype_base::digit, 'a'));
    CHECK(ctype.toupper('q') == 'Q' && ctype.is(std::ctype_base::punct, '!'));

    // A facet of the program's own, and numbers read and written in the locale.
    std::ostringstream grouped;
    grouped.imbue(std::locale(classic, new Grouping));
    grouped << 1234567;
    std::printf("cxx-probe: numpunct facet of the program: %s\n", grouped.str().c_str());
    CHECK(grouped.str() == "1'234'567");

    std::printf("cxx-probe: to_string %s %s, stod %g, stof %g, stold %Lg\n",
                std::to_string(3.5).c_str(), std::to_string(-12).c_str(), std::stod("2.5e3"),
                std::stof("0.25"), std::stold("1.5"));
    CHECK(std::stod("2.5e3") == 2500.0 && std::stof("0.25") == 0.25f && std::stold("1.5") == 1.5L);
    CHECK(std::to_string(3.5) == "3.500000");

    // charconv (the parser of LLVM libc's header library) and chars_format.
    double parsed = 0;
    const char text[] = "6.25e1";
    auto result = std::from_chars(text, text + sizeof(text) - 1, parsed);
    char buffer[32];
    auto written = std::to_chars(buffer, buffer + sizeof(buffer), 0.1);
    *written.ptr = 0;
    std::printf("cxx-probe: from_chars %g (%d), to_chars %s\n", parsed,
                result.ec == std::errc(), buffer);
    CHECK(result.ec == std::errc() && parsed == 62.5 && std::strcmp(buffer, "0.1") == 0);

    // A named locale that does not exist is an exception, as in POSIX.
    bool thrown = false;
    try {
        std::locale missing("xx_XX.UTF-8");
        (void)missing;
    } catch (const std::runtime_error &) {
        thrown = true;
    }
    std::printf("cxx-probe: std::locale of an unknown name throws runtime_error: %d\n", thrown ? 1 : 0);
    CHECK(thrown);
    std::locale named("C");
    std::printf("cxx-probe: std::locale(\"C\") name %s\n", named.name().c_str());
    CHECK(named.name() == "C");
}

// ---- terminate ------------------------------------------------------------

[[noreturn]] static void terminate_handler_of_the_probe() {
    const char line[] = "cxx-probe: terminate handler ran for an uncaught exception\n";
    ssize_t n = write(1, line, sizeof(line) - 1);
    (void)n;
    _exit(7);
}

static void handler_that_throws(int) { throw MyError("from a signal handler", 5); }

// An exception thrown by a signal handler leaves through the frame of the
// signal and is caught in the function that raised the signal. A child of
// fork does it, so that the handler's state cannot reach the other checks.
static void check_exception_from_signal_handler() {
    std::fflush(stdout);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        struct sigaction action;
        std::memset(&action, 0, sizeof action);
        action.sa_handler = handler_that_throws;
        sigemptyset(&action.sa_mask);
        action.sa_flags = SA_NODEFER;
        CHECK(sigaction(SIGUSR1, &action, nullptr) == 0);
        int code = 0;
        try {
            raise(SIGUSR1);
        } catch (const MyError &e) {
            code = e.code;
        }
        std::printf("cxx-probe: exception thrown by a signal handler caught after raise: code %d\n",
                    code);
        std::fflush(stdout);
        _exit(code == 5 ? 0 : 3);
    }
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void check_terminate() {
    std::fflush(stdout);
    pid_t pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        std::set_terminate(terminate_handler_of_the_probe);
        throw 5;  // nothing catches it
    }
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid);
    std::printf("cxx-probe: uncaught exception ends in std::terminate: child exit %d\n",
                WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 7);

    std::fflush(stdout);
    pid = fork();
    CHECK(pid >= 0);
    if (pid == 0) {
        throw std::runtime_error("nothing catches this");
    }
    CHECK(waitpid(pid, &status, 0) == pid);
    std::printf("cxx-probe: the default terminate aborts: signal %d\n",
                WIFSIGNALED(status) ? WTERMSIG(status) : -1);
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT);
}

static int run_checks() {
    running_checks = true;
    main_thread = std::this_thread::get_id();
    // The static objects were made before main.
    std::printf("cxx-probe: static constructors ran before main: %d, string %s\n",
                constructed_before_main, static_string.c_str());
    CHECK(constructed_before_main == 2 && static_string == "a static string of the library");
    std::atexit(at_exit_one);
    Static third_static("third, a local static");  // destroyed with main's locals, first
    static Static function_static("function static");
    std::atexit(at_exit_two);
    check_exceptions();
    check_rtti();
    check_streams_and_locales();
    check_exception_from_signal_handler();
    check_terminate();
    check_threads();
    check_atomic_wait();
    say("ok");
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && std::strcmp(argv[1], "run") == 0) return run_checks();
    char *child_argv[] = {const_cast<char *>("/bin/cxx-probe"), const_cast<char *>("run"), nullptr};
    pid_t pid = 0;
    CHECK(posix_spawn(&pid, "/bin/cxx-probe", nullptr, nullptr, child_argv, environ) == 0);
    int status = 0;
    CHECK(waitpid(pid, &status, 0) == pid);
    std::printf("cxx-probe: the program ended with status %d\n",
                WIFEXITED(status) ? WEXITSTATUS(status) : -1);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}
