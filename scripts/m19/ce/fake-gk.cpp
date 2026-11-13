// A stand-in for android.hardware.gatekeeper@1.0.so, built with clang and real libc++ (std::__1) so that
// gk.cpp's hand-laid layouts meet the real ones: std::string, std::function and its copy, the hidden return
// slots, and verify at vtable + 0x70. It copies the callback twice, as the HIDL proxy does
// (BpHwGatekeeper::verify to _hidl_verify), before calling it. Test only, never staged.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>

namespace android {
namespace hardware {

template <typename T>
struct hidl_vec {
    union {
        T* buffer;
        uint64_t pad;
    } mBuffer;
    uint32_t mSize;
    bool mOwnsBuffer;
};
static_assert(sizeof(hidl_vec<uint8_t>) == 16, "hidl_vec");

struct Return {
    int32_t exception = 0;
    int32_t error = 0;
    const char* message = nullptr;
    void* reserved = nullptr;
    bool checked = false;
    ~Return() {}
};

namespace gatekeeper {
namespace V1_0 {

struct GatekeeperResponse {
    int32_t code;
    uint32_t timeout;
    hidl_vec<uint8_t> data;
};

struct Sp {
    void* object = nullptr;
    ~Sp() {}
};

class IGatekeeper {
public:
    virtual ~IGatekeeper() {}
    virtual void slot2() {}
    virtual void slot3() {}
    virtual void slot4() {}
    virtual void slot5() {}
    virtual void slot6() {}
    virtual void slot7() {}
    virtual void slot8() {}
    virtual void slot9() {}
    virtual void slot10() {}
    virtual void slot11() {}
    virtual void slot12() {}
    virtual void slot13() {}
    virtual Return verify(uint32_t uid, uint64_t challenge, const hidl_vec<uint8_t>& enrolled, const hidl_vec<uint8_t>& provided,
                          std::function<void(const GatekeeperResponse&)> callback);
    static Sp getService(const std::string& name, bool getStub);
};

static_assert(sizeof(std::function<void(const GatekeeperResponse&)>) == 48, "libc++ std::function");

static uint8_t token[69];

static Return deliver(std::function<void(const GatekeeperResponse&)> callback, const GatekeeperResponse& response)
{
    std::function<void(const GatekeeperResponse&)> copy = callback; // the proxy's second copy
    copy(response);
    return Return();
}

Return IGatekeeper::verify(uint32_t uid, uint64_t challenge, const hidl_vec<uint8_t>& enrolled, const hidl_vec<uint8_t>& provided,
                           std::function<void(const GatekeeperResponse&)> callback)
{
    const char* mode = std::getenv("M19_FAKE_GK");
    mode = mode ? mode : "ok";
    std::fprintf(stderr, "fake-gk uid=%u challenge=%llu enrolled=%u provided=%u\n", uid, static_cast<unsigned long long>(challenge),
                 enrolled.mSize, provided.mSize);
    if (!std::strcmp(mode, "transport")) {
        Return failed;
        failed.exception = -32; // EX_TRANSACTION_FAILED
        return failed;
    }
    if (!std::strcmp(mode, "silent"))
        return Return();
    GatekeeperResponse response = {};
    bool expected = uid == 100007 && challenge == 0 && enrolled.mSize == 58 && provided.mSize == 64;
    for (uint32_t i = 0; expected && i < enrolled.mSize; i++)
        expected = enrolled.mBuffer.buffer[i] == static_cast<uint8_t>(i * 3);
    for (uint32_t i = 0; expected && i < provided.mSize; i++)
        expected = provided.mBuffer.buffer[i] == static_cast<uint8_t>(0xa0 + i);
    if (!std::strcmp(mode, "retry")) {
        response.code = -2;
        response.timeout = 30000;
    } else if (!expected || !std::strcmp(mode, "reject")) {
        response.code = -1;
    } else {
        for (unsigned i = 0; i < sizeof(token); i++)
            token[i] = static_cast<uint8_t>(i + 1);
        token[0] = 0;
        response.code = !std::strcmp(mode, "reenroll") ? 1 : 0;
        response.data.mBuffer.buffer = token;
        response.data.mSize = !std::strcmp(mode, "large") ? 4096 : sizeof(token);
    }
    return deliver(callback, response);
}

Sp IGatekeeper::getService(const std::string& name, bool getStub)
{
    static IGatekeeper service;
    Sp result;
    if (name == "default" && !getStub && !std::getenv("M19_FAKE_GK_ABSENT"))
        result.object = &service;
    return result;
}

}  // namespace V1_0
}  // namespace gatekeeper
}  // namespace hardware
}  // namespace android
