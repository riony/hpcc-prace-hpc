// T88 example: C++ with threads (g++ from module gcc/11.5). Prints one line per thread.
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>
#include <sched.h>
#include <unistd.h>

int main() {
    char host[256] = {0};
    gethostname(host, sizeof host - 1);
    cpu_set_t cpus;                       // the CPUs this job was given, not the whole node
    int n = sched_getaffinity(0, sizeof cpus, &cpus) == 0 ? CPU_COUNT(&cpus) : 1;
    std::mutex m;
    std::vector<std::thread> pool;
    for (int i = 0; i < n; ++i)
        pool.emplace_back([&, i] { std::lock_guard<std::mutex> g(m); std::cout << "thread " << i << " on " << host << "\n"; });
    for (auto &t : pool) t.join();
    std::cout << "cxx threads ok: " << pool.size() << " threads on " << host << std::endl;
    return 0;
}
