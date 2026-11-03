// Keystore2 binding for the M19 client: the calls TWRP's vold makes, keeping no upgraded blob.
#ifdef M19_BINDING_TEST
#include "binding-test-api.h"
#else
#include <aidl/android/hardware/security/keymint/BlockMode.h>
#include <aidl/android/hardware/security/keymint/KeyParameter.h>
#include <aidl/android/hardware/security/keymint/KeyParameterValue.h>
#include <aidl/android/hardware/security/keymint/KeyPurpose.h>
#include <aidl/android/hardware/security/keymint/PaddingMode.h>
#include <aidl/android/hardware/security/keymint/SecurityLevel.h>
#include <aidl/android/hardware/security/keymint/Tag.h>
#include <aidl/android/system/keystore2/CreateOperationResponse.h>
#include <aidl/android/system/keystore2/Domain.h>
#include <aidl/android/system/keystore2/EphemeralStorageKeyResponse.h>
#include <aidl/android/system/keystore2/IKeystoreOperation.h>
#include <aidl/android/system/keystore2/IKeystoreSecurityLevel.h>
#include <aidl/android/system/keystore2/IKeystoreService.h>
#include <aidl/android/system/keystore2/KeyDescriptor.h>
#include <android/binder_auto_utils.h>
#endif
#include <dlfcn.h>

#include <cstring>
#include <memory>
#include <optional>
#include <vector>
#include <cerrno>
#include <cstdlib>
#include <utility>

#include "binding.h"
#include "core.h"

namespace ks2 = ::aidl::android::system::keystore2;
namespace km = ::aidl::android::hardware::security::keymint;

namespace {

constexpr char kService[] = "android.system.keystore2.IKeystoreService/default";
constexpr int64_t kVoldNamespace = 100;
constexpr int32_t kMacBits = M19_MAC_BYTES * 8;

struct Context {
    std::shared_ptr<ks2::IKeystoreSecurityLevel> level;
    m19_probe_progress progress = nullptr;
    void* progress_context = nullptr;
    m19_upgrade_fact upgrade = M19_U_NOT_ATTEMPTED;
    int observed = 0;
};

Context& state() { static Context context; return context; }

void advance(Context* c, m19_probe_stage stage) {
    if (stage == M19_P_CREATE || stage == M19_P_EPHEMERAL) c->upgrade = M19_U_UNKNOWN;
    if (c->progress) c->progress(c->progress_context, stage, c->upgrade, c->observed);
}

int failed(Context* c, int* detail, int code = 0) {
    if (code) *detail = code;
    if (c->upgrade != M19_U_NOT_ATTEMPTED) c->upgrade = M19_U_UNKNOWN;
    return M19_KS_ERROR;
}

using Marker = void (*)(const AParcel*);
void* platform_open() {
#ifdef M19_BINDING_TEST
    return m19_test_open();
#else
    return dlopen("libbinder_ndk.so", RTLD_NOW);
#endif
}
void* platform_symbol(void* library, const char* name) {
#ifdef M19_BINDING_TEST
    return m19_test_symbol(library, name);
#else
    return dlsym(library, name);
#endif
}
Marker sensitive_marker() {
    static const Marker mark = [] {
        void* library = platform_open();
        return library ? reinterpret_cast<Marker>(platform_symbol(library, "AParcel_markSensitive")) : nullptr;
    }();
    return mark;
}

void wipe(std::vector<uint8_t>& v) { m19_wipe(v.data(), v.size()); }
void wipe(std::optional<std::vector<uint8_t>>& v) { if (v) wipe(*v); }
void wipe(std::vector<km::KeyParameter>& v) {
    for (auto& p : v) if (p.value.getTag() == km::KeyParameterValue::Tag::blob)
        wipe(p.value.get<km::KeyParameterValue::Tag::blob>());
}

// Own every explicit sensitive C++ copy before the first allocation/RPC.
// No accumulating plaintext vector: bounded returned parts copy directly into
// core-owned output, which core wipes. This avoids secret-bearing reallocations.
struct Call {
    ks2::KeyDescriptor key;
    std::vector<km::KeyParameter> parameters;
    ks2::CreateOperationResponse create;
    ks2::EphemeralStorageKeyResponse ephemeral;
    std::vector<uint8_t> body;
    std::optional<std::vector<uint8_t>> part;
    uint8_t* output;
    size_t capacity;
    bool committed = false;
    Call(uint8_t* p, size_t n) : output(p), capacity(n) {}
    ~Call() {
        wipe(key.blob); wipe(parameters); wipe(create.upgradedBlob);
        if (create.parameters) wipe(create.parameters->keyParameter);
        wipe(ephemeral.ephemeralKey); wipe(ephemeral.upgradedBlob);
        wipe(body); wipe(part);
        if (!committed) m19_wipe(output, capacity);
    }
    void descriptor(const uint8_t* blob, size_t size) {
        key.domain = ks2::Domain::BLOB; key.nspace = kVoldNamespace;
        key.blob.emplace(blob, blob + size);
    }
    bool append(size_t* used) {
        if (!part) return true;
        if (*used > capacity || part->size() > capacity - *used) return false;
        if (!part->empty()) std::memcpy(output + *used, part->data(), part->size());
        *used += part->size(); wipe(part); part.reset(); return true;
    }
};

bool observe_upgrade(Context* c, const std::optional<std::vector<uint8_t>>& blob) {
    if (!blob) return true;
    c->observed = 1;
    c->upgrade = M19_U_OBSERVED;
    if (blob->empty() || blob->size() > M19_KEY_MAX) return false;
    return true;
}

int status_detail(const ndk::ScopedAStatus& status) {
    if (status.getExceptionCode() == EX_SERVICE_SPECIFIC) return status.getServiceSpecificError();
    return status.getExceptionCode() ? status.getExceptionCode() : status.getStatus();
}

template <km::KeyParameterValue::Tag kind, typename Value>
km::KeyParameter parameter(km::Tag tag, Value value) {
    km::KeyParameter result;
    result.tag = tag;
    result.value = km::KeyParameterValue::make<kind>(std::move(value));
    return result;
}

int connect(void* opaque, int* detail) {
    using Check = AIBinder* (*)(const char*);
    auto* context = static_cast<Context*>(opaque);
    try {
    *detail = -ENOSYS;
    if (!sensitive_marker()) return M19_KS_ERROR;
    void* library = platform_open();
    if (!library) return M19_KS_ERROR;
    auto check = reinterpret_cast<Check>(platform_symbol(library, "AServiceManager_checkService"));
    if (!check) return M19_KS_ERROR;
    advance(context, M19_P_LOOKUP);
    ndk::SpAIBinder binder(check(kService));
    auto service = ks2::IKeystoreService::fromBinder(binder);
    if (!service) { *detail = -ENOENT; return M19_KS_ERROR; }
    advance(context, M19_P_LEVEL);
    auto status = service->getSecurityLevel(km::SecurityLevel::TRUSTED_ENVIRONMENT, &context->level);
    *detail = status_detail(status);
    return status.isOk() && context->level ? M19_KS_OK : M19_KS_ERROR;
    } catch (...) { return failed(context, detail, -EFAULT); }
}

int decrypt(void* opaque, const m19_decrypt_request* request, uint8_t* output, size_t capacity, size_t* size, int* detail) {
    auto* context = static_cast<Context*>(opaque);
    *size = 0;
    Call call(output, capacity);
    try {
    using Kind = km::KeyParameterValue::Tag;
    auto& parameters = call.parameters;
    parameters.reserve(6);
    parameters.push_back(parameter<Kind::blockMode>(km::Tag::BLOCK_MODE, km::BlockMode::GCM));
    parameters.push_back(parameter<Kind::paddingMode>(km::Tag::PADDING, km::PaddingMode::NONE));
    parameters.push_back(parameter<Kind::integer>(km::Tag::MAC_LENGTH, kMacBits));
    parameters.push_back(parameter<Kind::blob>(km::Tag::APPLICATION_ID,
                                               std::vector<uint8_t>(request->app_id, request->app_id + request->app_id_size)));
    parameters.push_back(parameter<Kind::blob>(km::Tag::NONCE, std::vector<uint8_t>(request->nonce, request->nonce + request->nonce_size)));
    parameters.push_back(parameter<Kind::keyPurpose>(km::Tag::PURPOSE, km::KeyPurpose::DECRYPT));

    call.descriptor(request->blob, request->blob_size);
    auto& response = call.create;
    advance(context, M19_P_CREATE);
    auto status = context->level->createOperation(call.key, parameters, true, &response);
    *detail = status_detail(status);
    bool valid_upgrade = observe_upgrade(context, response.upgradedBlob);
    if (!status.isOk()) return failed(context, detail);
    if (!valid_upgrade || !response.iOperation) return failed(context, detail, -EPROTO);
    wipe(response.upgradedBlob); response.upgradedBlob.reset();
    context->upgrade = context->observed ? M19_U_OBSERVED : M19_U_NONE_OBSERVED;
    call.body.assign(request->body_and_mac, request->body_and_mac + request->body_and_mac_size);
    advance(context, M19_P_UPDATE);
    status = response.iOperation->update(call.body, &call.part);
    *detail = status_detail(status);
    if (!status.isOk()) return failed(context, detail);
    if (!call.append(size)) return failed(context, detail, -EOVERFLOW);
    advance(context, M19_P_FINISH);
    status = response.iOperation->finish(std::nullopt, std::nullopt, &call.part);
    *detail = status_detail(status);
    if (!status.isOk()) return failed(context, detail);
    if (!call.append(size) || !*size) return failed(context, detail, -EPROTO);
    call.committed = true;
    return context->observed ? M19_KS_UPGRADE : M19_KS_OK;
    } catch (...) {
        (void)observe_upgrade(context, call.create.upgradedBlob);
        return failed(context, detail, -EFAULT);
    }
}

int ephemeral(void* opaque, const uint8_t* storage_key, size_t storage_key_size, uint8_t* output, size_t capacity, size_t* size, int* detail) {
    auto* context = static_cast<Context*>(opaque);
    *size = 0;
    Call call(output, capacity);
    try {
    call.descriptor(storage_key, storage_key_size);
    auto& response = call.ephemeral;
    advance(context, M19_P_EPHEMERAL);
    auto status = context->level->convertStorageKeyToEphemeral(call.key, &response);
    *detail = status_detail(status);
    bool valid_upgrade = observe_upgrade(context, response.upgradedBlob);
    if (!status.isOk()) return failed(context, detail);
    if (!valid_upgrade) return failed(context, detail, -EPROTO);
    if (response.upgradedBlob) return M19_KS_UPGRADE;
    if (response.ephemeralKey.empty() || response.ephemeralKey.size() > capacity)
        return failed(context, detail, -EPROTO);
    std::memcpy(output, response.ephemeralKey.data(), response.ephemeralKey.size());
    *size = response.ephemeralKey.size();
    context->upgrade = context->observed ? M19_U_OBSERVED : M19_U_NONE_OBSERVED;
    call.committed = true;
    return M19_KS_OK;
    } catch (...) {
        (void)observe_upgrade(context, call.ephemeral.upgradedBlob);
        return failed(context, detail, -EFAULT);
    }
}

const m19_keystore_ops kOps = {connect, decrypt, ephemeral};

}  // namespace

// The generated proxies call this for sensitive interfaces, and the NDK stub does not export it.
// Forwarding keeps the behaviour: the parcel holding key material is wiped when it is freed.
extern "C" void AParcel_markSensitive(const AParcel* parcel) {
    Marker mark = sensitive_marker();
    if (!mark) std::_Exit(125); // No silent downgrade of sensitive parcel handling.
    mark(parcel);
}

const m19_keystore_ops* m19_keystore2_ops() { return &kOps; }

void* m19_keystore2_context() {
    return &state();
}

void m19_keystore2_progress(m19_probe_progress callback, void* context) {
    state().progress = callback; state().progress_context = context;
}
m19_upgrade_fact m19_keystore2_upgrade() { return state().upgrade; }
int m19_keystore2_upgrade_observed() { return state().observed; }
