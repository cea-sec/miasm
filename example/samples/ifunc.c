// Compile with gcc -masm=intel -o ifunc ifunc.c

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
void pxor_c(uint64_t a[2], uint64_t b[2]) {
    printf("in boring ver.\n");
    a[0] ^= b[0];
    a[1] ^= b[1];
}
void pxor_sse2(uint64_t a[2], uint64_t b[2]) {
    printf("in sse2 ver.\n");
    asm("MOVDQA xmm1, [%1]\n\t"
        "MOVDQA xmm2, [%2]\n\t"
        "PXOR xmm1, xmm2"
        : "+r" (a)
        : "r" (a),
          "r" (b)
    );
}

void pxor(uint64_t a[2], uint64_t b[2]) __attribute__((ifunc("resolve_pxor")));

static void *resolve_pxor() {
    printf("sse2 support is %b\n", __builtin_cpu_supports("sse2"));
    if (__builtin_cpu_supports("sse2")) {
        return pxor_sse2;
    }
    return pxor_c;
}

int main(void) {
    uint64_t a[2] = {0x1337, 0xBEEF};
    uint64_t b[2] = {0xBABA, 0x15DA};
    pxor(a, b);
    return EXIT_SUCCESS;
}
