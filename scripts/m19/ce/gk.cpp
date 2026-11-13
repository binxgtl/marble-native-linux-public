// IGatekeeper/default verify through the island's own android.hardware.gatekeeper@1.0.so, as TWRP calls it
// (docs/m19-r7.md). The proxy and libhidlbase are platform C++ (libc++ std::__1); this binary's C++ runtime is
// the NDK's, so nothing of either standard library crosses the boundary. The few platform objects involved are
// laid out by hand here, each as TWRP's recovery binary uses it, and test-gk.cpp checks every layout against a
// fake built with real libc++ and real C++ types. Only verify is reachable: enroll, deleteUser and
// deleteAllUsers have no path in this file.
#include <dlfcn.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "gk.h"

namespace {

constexpr char kGetService[] =
    "_ZN7android8hardware10gatekeeper4V1_011IGatekeeper10getServiceERKNSt3__112basic_stringIcNS4_11char_traitsIcEENS4_"
    "9allocatorIcEEEEb";
// IGatekeeper::verify's slot: TWRP's recovery calls it at vtable + 0x70.
constexpr size_t kVerifySlot = 0x70 / sizeof(void*);
constexpr uint32_t kChallenge = 0;
constexpr int32_t kStatusOk = 0, kStatusReenroll = 1, kRetryTimeout = -2;

// libc++ std::string, short form, little-endian: byte 0 holds size << 1, then the characters and a NUL.
struct PlatformShortString {
    uint8_t size_shifted;
    char text[23];
};
static_assert(sizeof(PlatformShortString) == 24, "libc++ string");

// hardware::hidl_vec<uint8_t>: a 64-bit pointer slot, uint32 size, bool ownsBuffer.
struct HidlVec {
    const uint8_t* buffer;
    uint32_t size;
    bool owns;
    uint8_t padding[3];
};
static_assert(sizeof(HidlVec) == 16, "hidl_vec");

// V1_0::GatekeeperResponse.
struct GkResponse {
    int32_t code;
    uint32_t timeout;
    HidlVec data;
};
static_assert(sizeof(GkResponse) == 24, "GatekeeperResponse");

// sp<IGatekeeper> and Return<void> are returned through a hidden pointer because they are not trivially
// copyable; these stand-ins have user-provided destructors for the same reason. The Return is never
// destroyed: only its leading exception code is read, so its later fields do not matter here.
struct SpOut {
    void* object;
    SpOut() : object(nullptr) {}
    ~SpOut() {}
    SpOut(const SpOut&) = delete;
};

struct ReturnOut {
    int32_t exception;
    uint8_t rest[124];
    ReturnOut() : exception(-1), rest() {}
    ~ReturnOut() {}
    ReturnOut(const ReturnOut&) = delete;
};

struct Callback;

// The object a libc++ std::function<void(const GatekeeperResponse&)> points at: a vtable and our context.
struct Target {
    const void* const* vtable;
    Callback* owner;
};

struct Callback {
    int calls = 0;
    int32_t code = 0;
    uint32_t timeout = 0;
    uint8_t* token = nullptr;
    size_t capacity = 0, size = 0;
    bool fits = true;
};

void target_noop(Target*) {}
Target* target_clone(const Target* self)
{
    auto* copy = static_cast<Target*>(std::malloc(sizeof(Target)));
    if (copy)
        *copy = *self;
    return copy;
}
void target_clone_into(const Target* self, Target* place)
{
    *place = *self;
}
void target_free(Target* self)
{
    std::free(self);
}
void target_call(Target* self, const GkResponse* response)
{
    Callback* owner = self->owner;
    owner->calls++;
    owner->code = response->code;
    owner->timeout = response->timeout;
    if (response->code == kStatusOk || response->code == kStatusReenroll) {
        owner->fits = response->data.size <= owner->capacity;
        owner->size = owner->fits ? response->data.size : 0;
        if (owner->fits && owner->size)
            std::memcpy(owner->token, response->data.buffer, owner->size);
    }
}
const void* target_none(const Target*, const void*)
{
    return nullptr;
}
const void* target_type(const Target*)
{
    static const char unused = 0;
    return &unused;
}

// libc++'s __function::__base: two destructors, __clone(), __clone(p), destroy(), destroy_deallocate(),
// operator(), target(), target_type(). TWRP's recovery calls destroy and destroy_deallocate at +0x20 and +0x28.
const void* const kTargetVtable[] = {
    reinterpret_cast<const void*>(&target_noop),       reinterpret_cast<const void*>(&target_noop),
    reinterpret_cast<const void*>(&target_clone),      reinterpret_cast<const void*>(&target_clone_into),
    reinterpret_cast<const void*>(&target_noop),       reinterpret_cast<const void*>(&target_free),
    reinterpret_cast<const void*>(&target_call),       reinterpret_cast<const void*>(&target_none),
    reinterpret_cast<const void*>(&target_type),
};

// libc++ std::function: 32 bytes of 16-aligned inline storage, then __f_ (TWRP's recovery: __f_ at +0x20).
// Passed by value, so it travels as a pointer to this temporary; the callee copies it with __clone(p).
struct Function {
    alignas(16) unsigned char storage[32];
    Target* f;
    explicit Function(Callback* owner) : storage(), f(reinterpret_cast<Target*>(storage))
    {
        f->vtable = kTargetVtable;
        f->owner = owner;
    }
    Function(const Function& other) : storage(), f(reinterpret_cast<Target*>(storage))
    {
        *f = *other.f;
    }
    ~Function() {}
};
static_assert(sizeof(Function) == 48 && alignof(Function) == 16, "std::function");

using GetService = SpOut (*)(const PlatformShortString&, bool);
using Verify = ReturnOut (*)(void*, uint32_t, uint64_t, const HidlVec&, const HidlVec&, Function);

int connect(void* opaque, int* detail)
{
    auto* context = static_cast<m19_ce_gk_context*>(opaque);
    *detail = 0;
    void* library = dlopen(context->library, RTLD_NOW | RTLD_LOCAL);
    if (!library) {
        *detail = -2;
        return -1;
    }
    auto get = reinterpret_cast<GetService>(dlsym(library, kGetService));
    if (!get) {
        *detail = -3;
        return -1;
    }
    PlatformShortString name = {};
    static const char kName[] = "default";
    name.size_shifted = static_cast<uint8_t>((sizeof(kName) - 1) << 1);
    std::memcpy(name.text, kName, sizeof(kName));
    SpOut service = get(name, false);
    if (!service.object) {
        *detail = -19;
        return -1;
    }
    context->service = service.object; // The strong reference is kept until the process exits.
    return 0;
}

int verify(void* opaque, uint32_t uid, const uint8_t* handle, size_t handle_size, const uint8_t* provided, size_t provided_size,
           uint8_t* token, size_t capacity, size_t* token_size, uint32_t* timeout, int* detail)
{
    auto* context = static_cast<m19_ce_gk_context*>(opaque);
    *token_size = 0;
    *timeout = 0;
    *detail = 0;
    if (!context->service || handle_size > UINT32_MAX || provided_size > UINT32_MAX)
        return M19_GK_ERROR;
    HidlVec enrolled = {handle, static_cast<uint32_t>(handle_size), false, {}};
    HidlVec password = {provided, static_cast<uint32_t>(provided_size), false, {}};
    Callback callback;
    callback.token = token;
    callback.capacity = capacity;
    auto vtable = *static_cast<void* const* const*>(context->service);
    auto call = reinterpret_cast<Verify>(vtable[kVerifySlot]);
    ReturnOut result = call(context->service, uid, kChallenge, enrolled, password, Function(&callback));
    if (result.exception) {
        *detail = result.exception;
        return M19_GK_ERROR;
    }
    if (callback.calls != 1) {
        *detail = -61;
        return M19_GK_ERROR;
    }
    *detail = callback.code;
    if (callback.code == kStatusOk || callback.code == kStatusReenroll) {
        if (!callback.fits) {
            *detail = -75;
            return M19_GK_ERROR;
        }
        *token_size = callback.size;
        return M19_GK_OK;
    }
    if (callback.code == kRetryTimeout) {
        *timeout = callback.timeout;
        return M19_GK_RETRY;
    }
    return callback.code == -1 ? M19_GK_REJECTED : M19_GK_ERROR;
}

}  // namespace

extern "C" const struct m19_ce_gatekeeper m19_ce_gk_ops = {connect, verify};
