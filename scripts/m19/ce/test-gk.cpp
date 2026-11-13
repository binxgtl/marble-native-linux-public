// gk.cpp against fake-gk.so (real libc++): prints one status line per call. Test only.
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "gk.h"

int main(int argc, char** argv)
{
    if (argc != 2)
        return 64;
    m19_ce_gk_context context = {argv[1], nullptr};
    int detail = 0;
    if (m19_ce_gk_ops.connect(&context, &detail)) {
        std::printf("GK connect=%d\n", detail);
        return 1;
    }
    uint8_t handle[58], provided[64], token[69 + 1] = {};
    for (unsigned i = 0; i < sizeof(handle); i++)
        handle[i] = static_cast<uint8_t>(i * 3);
    for (unsigned i = 0; i < sizeof(provided); i++)
        provided[i] = static_cast<uint8_t>(0xa0 + i);
    size_t size = 0;
    uint32_t timeout = 0;
    int result = m19_ce_gk_ops.verify(&context, 100007, handle, sizeof(handle), provided, sizeof(provided), token, sizeof(token), &size,
                                      &timeout, &detail);
    int token_ok = size == 69 && token[0] == 0;
    for (unsigned i = 1; token_ok && i < 69; i++)
        token_ok = token[i] == i + 1;
    std::printf("GK result=%d detail=%d size=%zu timeout=%u token_ok=%d\n", result, detail, size, timeout, token_ok);
    return 0;
}
