/*
 * Copyright (C) 2017 GlobalLogic
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OPTEE_KEYMASTER_H
#define OPTEE_KEYMASTER_H

#include <android/hardware/keymaster/3.0/IKeymasterDevice.h>
#include <hidl/Status.h>

#include <hidl/MQDescriptor.h>
#include <hardware/keymaster_defs.h>
#include <common.h>

namespace android {
namespace hardware {
namespace keymaster {
namespace V3_0 {
namespace optee {

using ::android::hardware::keymaster::V3_0::ErrorCode;
using ::android::hardware::keymaster::V3_0::IKeymasterDevice;
using ::android::hardware::keymaster::V3_0::KeyCharacteristics;
using ::android::hardware::keymaster::V3_0::KeyFormat;
using ::android::hardware::keymaster::V3_0::KeyParameter;
using ::android::hardware::keymaster::V3_0::KeyPurpose;
using ::android::hardware::Return;
using ::android::hardware::Void;
using ::android::hardware::hidl_vec;
using ::android::hardware::hidl_string;
using ::android::sp;

class KmParamSet: public keymaster_key_param_set_t {
public:
	KmParamSet();
    KmParamSet(const hidl_vec<KeyParameter> &keyParams);
    KmParamSet(KmParamSet &&other);
    KmParamSet(const KmParamSet &) = delete;
    ~KmParamSet();
};

class OpteeKeymasterDevice: public IKeymasterDevice {
public:
    OpteeKeymasterDevice();
    ~OpteeKeymasterDevice();
    bool getIsConnected();

    Return<void> getHardwareFeatures(getHardwareFeatures_cb _hidl_cb);
    Return<ErrorCode> addRngEntropy(const hidl_vec<uint8_t> &data) override;
    Return<void> generateKey(const hidl_vec<KeyParameter> &keyParams,
                    generateKey_cb _hidl_cb) override;
    Return<void> getKeyCharacteristics(const hidl_vec<uint8_t> &keyBlob,
                    const hidl_vec<uint8_t> &clientId,
                    const hidl_vec<uint8_t> &appData,
                    getKeyCharacteristics_cb _hidl_cb) override;
    Return<void> importKey(const hidl_vec<KeyParameter> &params, KeyFormat keyFormat,
                    const hidl_vec<uint8_t> &keyData, importKey_cb _hidl_cb) override;
    Return<void> exportKey(KeyFormat exportFormat, const hidl_vec<uint8_t> &keyBlob,
                    const hidl_vec<uint8_t> &clientId, const hidl_vec<uint8_t> &appData,
                    exportKey_cb _hidl_cb) override;
    Return<void> attestKey(const hidl_vec<uint8_t> &keyToAttest,
                    const hidl_vec<KeyParameter> &attestParams,
                    attestKey_cb _hidl_cb) override;
    Return<void> upgradeKey(const hidl_vec<uint8_t> &keyBlobToUpgrade,
                    const hidl_vec<KeyParameter> &upgradeParams,
                    upgradeKey_cb _hidl_cb) override;
    Return<ErrorCode> deleteKey(const hidl_vec<uint8_t> &keyBlob) override;
    Return<ErrorCode> deleteAllKeys() override;
    Return<ErrorCode> destroyAttestationIds() override;
    Return<void> begin(KeyPurpose purpose, const hidl_vec<uint8_t> &key,
                    const hidl_vec<KeyParameter> &inParams, begin_cb _hidl_cb) override;
    Return<void> update(uint64_t operationHandle, const hidl_vec<KeyParameter> &inParams,
                    const hidl_vec<uint8_t> &input, update_cb _hidl_cb) override;
    Return<void> finish(uint64_t operationHandle, const hidl_vec<KeyParameter> &inParams,
                    const hidl_vec<uint8_t> &input, const hidl_vec<uint8_t> &signature,
                    finish_cb _hidl_cb) override;
    Return<ErrorCode> abort(uint64_t operationHandle) override;

private:
    bool connect();
    void disconnect();
    bool checkConnection(ErrorCode &rc);

    int getParamSetBlobSize(const KmParamSet &paramSet);
    int getParamSetSize(const KmParamSet &paramSet);
    int getBlobSize(const keymaster_blob_t &blob);
    int getKeyBlobSize(const keymaster_key_blob_t &keyBlob);

    int osVersion(uint32_t *in);
    int osPatchlevel(uint32_t *in);
    int verifiedBootState(uint8_t *in);

    /*Serializers*/
    int serializeData(uint8_t *dest, const size_t count,
			const uint8_t *source, const size_t objSize);
    int serializeSize(uint8_t *dest, const size_t size);
    int serializeOperationHandle(uint8_t *dest, const uint64_t handle);
    int serializeParamSet(uint8_t *dest,
			const KmParamSet &paramSet);
    int serializePresence(uint8_t *dest, const presence p);
    int serializeParamSetWithPresence(uint8_t *dest,
			const KmParamSet &params);
    int serializeBlobWithPresenceInfo(uint8_t *dest,
			const keymaster_blob_t &blob, bool presence);
    int serializeKeyFormat(uint8_t *dest,
			const keymaster_key_format_t &keyFormat);

    /*Deserializers*/
    int deserializeSize(size_t &size, const uint8_t *source);
    int deserializeKeyBlob(keymaster_key_blob_t &keyBlob,
			const uint8_t *source, ErrorCode &rc);
    int deserializeBlob(keymaster_blob_t &blob,
			const uint8_t *source, ErrorCode &rc);
    int deserializeKeyCharacteristics(keymaster_key_characteristics_t &characteristics,
			const uint8_t *source, ErrorCode &rc);
    int deserializeParamSet(KmParamSet &params,
			const uint8_t *source, ErrorCode &rc);

    bool is_connected_;
    const uint32_t recv_buf_size_ = 8 * 1024;

    const bool supports_symmetric_cryptography_ = true;
    const bool supports_attestation_ = true;
    const bool supports_ec_ = true;
    const bool supports_all_digests_ = true;
    const bool is_secure_ = true;
    const char *name_ = "OP-TEE Keymaster HALv3_0";
    const char *author_ = "OP-TEE Foundation";
};

} // namespace optee
} // namespace V3_0
} // namespace keymaster
} // namespace hardware
} // namespace android

#endif /* OPTEE_KEYMASTER_H */
