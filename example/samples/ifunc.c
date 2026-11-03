// Compile with gcc -fno-stack-protector -o ifunc ifunc.c

#include <stdbool.h>
#include <stdint.h>

const char *func_1() {
    return "zglorg";
}
const char *func_2() {
    return "bloups";
}

static bool use_func2;

char *func() __attribute__((ifunc("resolve_func")));

// Function pointer type matching `func` prototype
typedef const char *(*func_type)();

static func_type resolve_func() {
    if (use_func2) {
        return func_2;
    }
    return func_1;
}

char *wrapper() {
    return func();
}

int main() {
    wrapper();
    return 0;
}
