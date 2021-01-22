/*
 * Copyright (C) 2016 The Android Open Source Project
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

#define LOG_TAG "keymaster_hidl_hal_test"
#include <cutils/log.h>

#include <iostream>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/x509.h>

#include <android/hardware/keymaster/3.0/IKeymasterDevice.h>
#include <android/hardware/keymaster/3.0/types.h>

#include <cutils/properties.h>

#include <keymaster/keymaster_configuration.h>

#include "authorization_set.h"
#include "key_param_output.h"

#include <VtsHalHidlTargetTestBase.h>
#include <VtsHalHidlTargetTestEnvBase.h>

#include "attestation_record.h"
#include "openssl_utils.h"

#define KM_MAX_USE_TIMERS 32U
#define KM_MAX_USE_COUNTERS 20U

#define ARR_SIZE(a) (sizeof(a)/sizeof(a[0]))

using ::android::sp;
using ::std::string;

static bool arm_deleteAllKeys = false;
static bool dump_Attestations = false;

namespace android {
namespace hardware {

template <typename T> bool operator==(const hidl_vec<T>& a, const hidl_vec<T>& b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}

namespace keymaster {
namespace V3_0 {

bool operator==(const KeyParameter& a, const KeyParameter& b) {
    if (a.tag != b.tag) {
        return false;
    }

    switch (a.tag) {

    /* Boolean tags */
    case Tag::INVALID:
    case Tag::CALLER_NONCE:
    case Tag::INCLUDE_UNIQUE_ID:
    case Tag::ECIES_SINGLE_HASH_MODE:
    case Tag::BOOTLOADER_ONLY:
    case Tag::NO_AUTH_REQUIRED:
    case Tag::ALLOW_WHILE_ON_BODY:
    case Tag::EXPORTABLE:
    case Tag::ALL_APPLICATIONS:
    case Tag::ROLLBACK_RESISTANT:
    case Tag::RESET_SINCE_ID_ROTATION:
        return true;

    /* Integer tags */
    case Tag::KEY_SIZE:
    case Tag::MIN_MAC_LENGTH:
    case Tag::MIN_SECONDS_BETWEEN_OPS:
    case Tag::MAX_USES_PER_BOOT:
    case Tag::ALL_USERS:
    case Tag::USER_ID:
    case Tag::OS_VERSION:
    case Tag::OS_PATCHLEVEL:
    case Tag::MAC_LENGTH:
    case Tag::AUTH_TIMEOUT:
        return a.f.integer == b.f.integer;

    /* Long integer tags */
    case Tag::RSA_PUBLIC_EXPONENT:
    case Tag::USER_SECURE_ID:
        return a.f.longInteger == b.f.longInteger;

    /* Date-time tags */
    case Tag::ACTIVE_DATETIME:
    case Tag::ORIGINATION_EXPIRE_DATETIME:
    case Tag::USAGE_EXPIRE_DATETIME:
    case Tag::CREATION_DATETIME:
        return a.f.dateTime == b.f.dateTime;

    /* Bytes tags */
    case Tag::APPLICATION_ID:
    case Tag::APPLICATION_DATA:
    case Tag::ROOT_OF_TRUST:
    case Tag::UNIQUE_ID:
    case Tag::ATTESTATION_CHALLENGE:
    case Tag::ATTESTATION_APPLICATION_ID:
    case Tag::ATTESTATION_ID_BRAND:
    case Tag::ATTESTATION_ID_DEVICE:
    case Tag::ATTESTATION_ID_PRODUCT:
    case Tag::ATTESTATION_ID_SERIAL:
    case Tag::ATTESTATION_ID_IMEI:
    case Tag::ATTESTATION_ID_MEID:
    case Tag::ATTESTATION_ID_MANUFACTURER:
    case Tag::ATTESTATION_ID_MODEL:
    case Tag::ASSOCIATED_DATA:
    case Tag::NONCE:
    case Tag::AUTH_TOKEN:
        return a.blob == b.blob;

    /* Enum tags */
    case Tag::PURPOSE:
        return a.f.purpose == b.f.purpose;
    case Tag::ALGORITHM:
        return a.f.algorithm == b.f.algorithm;
    case Tag::BLOCK_MODE:
        return a.f.blockMode == b.f.blockMode;
    case Tag::DIGEST:
        return a.f.digest == b.f.digest;
    case Tag::PADDING:
        return a.f.paddingMode == b.f.paddingMode;
    case Tag::EC_CURVE:
        return a.f.ecCurve == b.f.ecCurve;
    case Tag::BLOB_USAGE_REQUIREMENTS:
        return a.f.keyBlobUsageRequirements == b.f.keyBlobUsageRequirements;
    case Tag::USER_AUTH_TYPE:
        return a.f.integer == b.f.integer;
    case Tag::ORIGIN:
        return a.f.origin == b.f.origin;

    /* Unsupported tags */
    case Tag::KDF:
        return false;
    }
}

bool operator==(const AuthorizationSet& a, const AuthorizationSet& b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

bool operator==(const KeyCharacteristics& a, const KeyCharacteristics& b) {
    // This isn't very efficient. Oh, well.
    AuthorizationSet a_sw(a.softwareEnforced);
    AuthorizationSet b_sw(b.softwareEnforced);
    AuthorizationSet a_tee(b.teeEnforced);
    AuthorizationSet b_tee(b.teeEnforced);

    a_sw.Sort();
    b_sw.Sort();
    a_tee.Sort();
    b_tee.Sort();

    return a_sw == b_sw && a_tee == b_sw;
}

::std::ostream& operator<<(::std::ostream& os, const AuthorizationSet& set) {
    if (set.size() == 0)
        os << "(Empty)" << ::std::endl;
    else {
        os << "\n";
        for (size_t i = 0; i < set.size(); ++i)
            os << set[i] << ::std::endl;
    }
    return os;
}

namespace test {
namespace {

template <TagType tag_type, Tag tag, typename ValueT>
bool contains(hidl_vec<KeyParameter>& set, TypedTag<tag_type, tag> ttag, ValueT expected_value) {
    size_t count = std::count_if(set.begin(), set.end(), [&](const KeyParameter& param) {
        return param.tag == tag && accessTagValue(ttag, param) == expected_value;
    });
    return count == 1;
}

template <TagType tag_type, Tag tag>
bool contains(hidl_vec<KeyParameter>& set, TypedTag<tag_type, tag>) {
    size_t count = std::count_if(set.begin(), set.end(),
                                 [&](const KeyParameter& param) { return param.tag == tag; });
    return count > 0;
}

constexpr char hex_value[256] = {0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 1,  2,  3,  4,  5,  6,  7, 8, 9, 0, 0, 0, 0, 0, 0,  // '0'..'9'
                                 0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 'A'..'F'
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 'a'..'f'
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  //
                                 0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0};

string hex2str(string a) {
    string b;
    size_t num = a.size() / 2;
    b.resize(num);
    for (size_t i = 0; i < num; i++) {
        b[i] = (hex_value[a[i * 2] & 0xFF] << 4) + (hex_value[a[i * 2 + 1] & 0xFF]);
    }
    return b;
}

string rsa_key = hex2str(
    "30820275020100300d06092a864886f70d01010105000482025f3082025b"
    "02010002818100c6095409047d8634812d5a218176e45c41d60a75b13901"
    "f234226cffe776521c5a77b9e389417b71c0b6a44d13afe4e4a2805d46c9"
    "da2935adb1ff0c1f24ea06e62b20d776430a4d435157233c6f916783c30e"
    "310fcbd89b85c2d56771169785ac12bca244abda72bfb19fc44d27c81e1d"
    "92de284f4061edfd99280745ea6d2502030100010281801be0f04d9cae37"
    "18691f035338308e91564b55899ffb5084d2460e6630257e05b3ceab0297"
    "2dfabcd6ce5f6ee2589eb67911ed0fac16e43a444b8c861e544a05933657"
    "72f8baf6b22fc9e3c5f1024b063ac080a7b2234cf8aee8f6c47bbf4fd3ac"
    "e7240290bef16c0b3f7f3cdd64ce3ab5912cf6e32f39ab188358afcccd80"
    "81024100e4b49ef50f765d3b24dde01aceaaf130f2c76670a91a61ae08af"
    "497b4a82be6dee8fcdd5e3f7ba1cfb1f0c926b88f88c92bfab137fba2285"
    "227b83c342ff7c55024100ddabb5839c4c7f6bf3d4183231f005b31aa58a"
    "ffdda5c79e4cce217f6bc930dbe563d480706c24e9ebfcab28a6cdefd324"
    "b77e1bf7251b709092c24ff501fd91024023d4340eda3445d8cd26c14411"
    "da6fdca63c1ccd4b80a98ad52b78cc8ad8beb2842c1d280405bc2f6c1bea"
    "214a1d742ab996b35b63a82a5e470fa88dbf823cdd02401b7b57449ad30d"
    "1518249a5f56bb98294d4b6ac12ffc86940497a5a5837a6cf946262b4945"
    "26d328c11e1126380fde04c24f916dec250892db09a6d77cdba351024077"
    "62cd8f4d050da56bd591adb515d24d7ccd32cca0d05f866d583514bd7324"
    "d5f33645e8ed8b4a1cb3cc4a1d67987399f2a09f5b3fb68c88d5e5d90ac3"
    "3492d6");

string ec_256_key = hex2str(
    "308187020100301306072a8648ce3d020106082a8648ce3d030107046d30"
    "6b0201010420737c2ecd7b8d1940bf2930aa9b4ed3ff941eed09366bc032"
    "99986481f3a4d859a14403420004bf85d7720d07c25461683bc648b4778a"
    "9a14dd8a024e3bdd8c7ddd9ab2b528bbc7aa1b51f14ebbbb0bd0ce21bcc4"
    "1c6eb00083cf3376d11fd44949e0b2183bfe");

string ec_521_key = hex2str(
    "3081EE020100301006072A8648CE3D020106052B810400230481D63081D3"
    "02010104420011458C586DB5DAA92AFAB03F4FE46AA9D9C3CE9A9B7A006A"
    "8384BEC4C78E8E9D18D7D08B5BCFA0E53C75B064AD51C449BAE0258D54B9"
    "4B1E885DED08ED4FB25CE9A1818903818600040149EC11C6DF0FA122C6A9"
    "AFD9754A4FA9513A627CA329E349535A5629875A8ADFBE27DCB932C05198"
    "6377108D054C28C6F39B6F2C9AF81802F9F326B842FF2E5F3C00AB7635CF"
    "B36157FC0882D574A10D839C1A0C049DC5E0D775E2EE50671A208431BB45"
    "E78E70BEFE930DB34818EE4D5C26259F5C6B8E28A652950F9F88D7B4B2C9"
    "D9");

class HidlBuf : public hidl_vec<uint8_t> {
    typedef hidl_vec<uint8_t> super;

  public:
    HidlBuf() {}
    HidlBuf(const super& other) : super(other) {}
    HidlBuf(super&& other) : super(std::move(other)) {}
    explicit HidlBuf(const std::string& other) : HidlBuf() { *this = other; }

    HidlBuf& operator=(const super& other) {
        super::operator=(other);
        return *this;
    }

    HidlBuf& operator=(super&& other) {
        super::operator=(std::move(other));
        return *this;
    }

    HidlBuf& operator=(const string& other) {
        resize(other.size());
        for (size_t i = 0; i < other.size(); ++i) {
            (*this)[i] = static_cast<uint8_t>(other[i]);
        }
        return *this;
    }

    string to_string() const { return string(reinterpret_cast<const char*>(data()), size()); }
};

}  // namespace

// Test environment for Keymaster HIDL HAL.
class KeymasterHidlEnvironment : public ::testing::VtsHalHidlTargetTestEnvBase {
   public:
    // get the test environment singleton
    static KeymasterHidlEnvironment* Instance() {
        static KeymasterHidlEnvironment* instance = new KeymasterHidlEnvironment;
        return instance;
    }

    virtual void registerTestServices() override { registerTestService<IKeymasterDevice>(); }
   private:
    KeymasterHidlEnvironment() {}
};

class KeymasterTest : public ::testing::VtsHalHidlTargetTestBase {
  public:

    void TearDown() override {
    }

    // SetUpTestCase runs only once per test case, not once per test.
    static void SetUpTestCase() {
        keymaster_ = ::testing::VtsHalHidlTargetTestBase::getService<IKeymasterDevice>(
            KeymasterHidlEnvironment::Instance()->getServiceName<IKeymasterDevice>());
        ASSERT_NE(keymaster_, nullptr);

        ASSERT_TRUE(
            keymaster_
                ->getHardwareFeatures([&](bool isSecure, bool supportsEc, bool supportsSymmetric,
                                          bool supportsAttestation, bool supportsAllDigests,
                                          const hidl_string& name, const hidl_string& author) {
                    //TODO: Add some initial check
            (void)(isSecure);
            (void)(supportsEc);
            (void)(supportsSymmetric);
            (void)(supportsAttestation);
            (void)(supportsAllDigests);
            (void)(name);
            (void)(author);
                })
                .isOk());
    }

    static void TearDownTestCase() { keymaster_.clear(); }

    AuthorizationSet UserAuths() { return AuthorizationSetBuilder().Authorization(TAG_USER_ID, 7); }

    ErrorCode GenerateKey(const AuthorizationSet& key_desc, HidlBuf* key_blob,
                          KeyCharacteristics* key_characteristics) {
        EXPECT_NE(key_blob, nullptr);
        EXPECT_NE(key_characteristics, nullptr);
        EXPECT_EQ(0U, key_blob->size());

        ErrorCode error;
        EXPECT_TRUE(keymaster_
                        ->generateKey(key_desc.hidl_data(),
                                      [&](ErrorCode hidl_error, const HidlBuf& hidl_key_blob,
                                          const KeyCharacteristics& hidl_key_characteristics) {
                                          error = hidl_error;
                                          *key_blob = hidl_key_blob;
                                          *key_characteristics = hidl_key_characteristics;
                                      })
                        .isOk());
        // On error, blob & characteristics should be empty.
        if (error != ErrorCode::OK) {
            EXPECT_EQ(0U, key_blob->size());
            EXPECT_EQ(0U, (key_characteristics->softwareEnforced.size() +
                           key_characteristics->teeEnforced.size()));
        }
        return error;
    }

    ErrorCode ImportKey(const AuthorizationSet& key_desc, KeyFormat format,
                        const string& key_material, HidlBuf* key_blob,
                        KeyCharacteristics* key_characteristics) {
        ErrorCode error;
        EXPECT_TRUE(keymaster_
                        ->importKey(key_desc.hidl_data(), format, HidlBuf(key_material),
                                    [&](ErrorCode hidl_error, const HidlBuf& hidl_key_blob,
                                        const KeyCharacteristics& hidl_key_characteristics) {
                                        error = hidl_error;
                                        *key_blob = hidl_key_blob;
                                        *key_characteristics = hidl_key_characteristics;
                                    })
                        .isOk());
        // On error, blob & characteristics should be empty.
        if (error != ErrorCode::OK) {
            EXPECT_EQ(0U, key_blob->size());
            EXPECT_EQ(0U, (key_characteristics->softwareEnforced.size() +
                           key_characteristics->teeEnforced.size()));
        }
        return error;
    }

    ErrorCode ExportKey(KeyFormat format, const HidlBuf& key_blob, const HidlBuf& client_id,
                        const HidlBuf& app_data, HidlBuf* key_material) {
        ErrorCode error;
        EXPECT_TRUE(
            keymaster_
                ->exportKey(format, key_blob, client_id, app_data,
                            [&](ErrorCode hidl_error_code, const HidlBuf& hidl_key_material) {
                                error = hidl_error_code;
                                *key_material = hidl_key_material;
                            })
                .isOk());
        // On error, blob should be empty.
        if (error != ErrorCode::OK) {
            EXPECT_EQ(0U, key_material->size());
        }
        return error;
    }

    ErrorCode DeleteKey(HidlBuf* key_blob, bool keep_key_blob = false) {
        auto rc = keymaster_->deleteKey(*key_blob);
        if (!keep_key_blob) *key_blob = HidlBuf();
        if (!rc.isOk()) return ErrorCode::UNKNOWN_ERROR;
        return rc;
    }

    ErrorCode DeleteAllKeys() {
        ErrorCode error = keymaster_->deleteAllKeys();
        return error;
    }

    ErrorCode GetCharacteristics(const HidlBuf& key_blob, const HidlBuf& client_id,
                                 const HidlBuf& app_data, KeyCharacteristics* key_characteristics) {
        ErrorCode error = ErrorCode::UNKNOWN_ERROR;
        EXPECT_TRUE(
            keymaster_
                ->getKeyCharacteristics(
                    key_blob, client_id, app_data,
                    [&](ErrorCode hidl_error, const KeyCharacteristics& hidl_key_characteristics) {
                        error = hidl_error, *key_characteristics = hidl_key_characteristics;
                    })
                .isOk());
        return error;
    }

    ErrorCode Begin(KeyPurpose purpose, const HidlBuf& key_blob, const AuthorizationSet& in_params,
                    AuthorizationSet* out_params, OperationHandle* op_handle) {
        SCOPED_TRACE("Begin");
        ErrorCode error;
        OperationHandle saved_handle = *op_handle;
        EXPECT_TRUE(
            keymaster_
                ->begin(purpose, key_blob, in_params.hidl_data(),
                        [&](ErrorCode hidl_error, const hidl_vec<KeyParameter>& hidl_out_params,
                            uint64_t hidl_op_handle) {
                            error = hidl_error;
                            *out_params = hidl_out_params;
                            *op_handle = hidl_op_handle;
			})
                .isOk());
        if (error != ErrorCode::OK) {
            // Some implementations may modify *op_handle on error.
            *op_handle = saved_handle;
        }
        return error;
    }

    ErrorCode Update(OperationHandle op_handle, const AuthorizationSet& in_params,
                     const string& input, AuthorizationSet* out_params, string* output,
                     size_t* input_consumed) {
        SCOPED_TRACE("Update");
        ErrorCode error;
        EXPECT_TRUE(keymaster_
                        ->update(op_handle, in_params.hidl_data(), HidlBuf(input),
                                 [&](ErrorCode hidl_error, uint32_t hidl_input_consumed,
                                     const hidl_vec<KeyParameter>& hidl_out_params,
                                     const HidlBuf& hidl_output) {
                                     error = hidl_error;
                                     out_params->push_back(AuthorizationSet(hidl_out_params));
                                     output->append(hidl_output.to_string());
                                     *input_consumed = hidl_input_consumed;
                                 })
                        .isOk());
        return error;
    }

    ErrorCode Finish(OperationHandle op_handle, const AuthorizationSet& in_params,
                     const string& input, const string& signature, AuthorizationSet* out_params,
                     string* output) {
        SCOPED_TRACE("Finish");
        ErrorCode error;
        EXPECT_TRUE(
            keymaster_
                ->finish(op_handle, in_params.hidl_data(), HidlBuf(input), HidlBuf(signature),
                         [&](ErrorCode hidl_error, const hidl_vec<KeyParameter>& hidl_out_params,
                             const HidlBuf& hidl_output) {
                             error = hidl_error;
                             *out_params = hidl_out_params;
                             output->append(hidl_output.to_string());
                         })
                .isOk());

        return error;
    }

    ErrorCode Abort(OperationHandle op_handle) {
        SCOPED_TRACE("Abort");
        auto retval = keymaster_->abort(op_handle);
        EXPECT_TRUE(retval.isOk());
        return retval;
    }

    ErrorCode AttestKey(const HidlBuf& key_blob, const AuthorizationSet& attest_params,
                        hidl_vec<hidl_vec<uint8_t>>* cert_chain) {
        SCOPED_TRACE("AttestKey");
        ErrorCode error;
        auto rc = keymaster_->attestKey(
            key_blob, attest_params.hidl_data(),
            [&](ErrorCode hidl_error, const hidl_vec<hidl_vec<uint8_t>>& hidl_cert_chain) {
                error = hidl_error;
                *cert_chain = hidl_cert_chain;
            });

        EXPECT_TRUE(rc.isOk()) << rc.description();
        if (!rc.isOk()) return ErrorCode::UNKNOWN_ERROR;

        return error;
    }

private:
    static sp<IKeymasterDevice> keymaster_;
};

sp<IKeymasterDevice> KeymasterTest::keymaster_;

class KeymasterTagTest : public KeymasterTest {
public:

    /* Make a default signing operation with Ecdsa key using default operation
       parameters and default message.*/
    ErrorCode DefaultEcdsaSigningOperation(const HidlBuf& key_blob) {
        string message(24, 'a');
        string signature;
        AuthorizationSet in_params = AuthorizationSetBuilder().Digest(Digest::NONE);
        AuthorizationSet out_params;
        OperationHandle op_handle;

        ErrorCode ret = Begin(KeyPurpose::SIGN, key_blob, in_params,
                              &out_params, &op_handle);

        if (ret != ErrorCode::OK) return ret;

        ret = Finish(op_handle, AuthorizationSet(), message, signature, &out_params,
                     &signature);

        if (ret != ErrorCode::OK) return ret;

        if (!out_params.empty())
            ret = ErrorCode:: UNKNOWN_ERROR;

        return ret;
    }
};

TEST_F(KeymasterTagTest, tag_MIN_SECONDS_BETWEEN_OPS) {
    HidlBuf key_blobs[KM_MAX_USE_TIMERS + 1];
    KeyCharacteristics key_characteristics[KM_MAX_USE_TIMERS + 1];
    unsigned int seconds = 100;

    for (unsigned int i = 0; i < ARR_SIZE(key_blobs); i++) {
         ASSERT_EQ(
            ErrorCode::OK,
            GenerateKey(AuthorizationSetBuilder()
                            .EcdsaSigningKey(256)
                            .Digest(Digest::NONE)
                            .Authorization(TAG_NO_AUTH_REQUIRED)
                            .Authorization(TAG_MIN_SECONDS_BETWEEN_OPS, seconds),
                        &key_blobs[i], &key_characteristics[i]));
    }

    for (unsigned int i = 0; i < ARR_SIZE(key_blobs) - 1; i++) {
        ASSERT_EQ(ErrorCode::OK, DefaultEcdsaSigningOperation(key_blobs[i]));
        ASSERT_EQ(ErrorCode::KEY_RATE_LIMIT_EXCEEDED, DefaultEcdsaSigningOperation(key_blobs[i]));
    }

    ASSERT_EQ(ErrorCode::TOO_MANY_OPERATIONS, DefaultEcdsaSigningOperation(key_blobs[KM_MAX_USE_TIMERS]));

    /* Sleep for seconds - waiting TAG_MIN_SECONDS_BETWEEN_OPS seconds for our tables to get cleaned */
    std::cout<<"Sleeping for " << seconds << " seconds\n";
    usleep(seconds * 1000000);

    ASSERT_EQ(ErrorCode::OK, DefaultEcdsaSigningOperation(key_blobs[0]));
    ASSERT_EQ(ErrorCode::KEY_RATE_LIMIT_EXCEEDED, DefaultEcdsaSigningOperation(key_blobs[0]));
}

/**
 * This test requires TA restart after finish if keys with tag MAX_USES_PER_BOOT
 * are expected.
 */
TEST_F(KeymasterTagTest, tag_MAX_USES_PER_BOOT) {
    HidlBuf key_blobs[KM_MAX_USE_COUNTERS + 1];
    KeyCharacteristics key_characteristics[KM_MAX_USE_COUNTERS + 1];
    unsigned int max_uses = 5;

    for (unsigned int i = 0; i < ARR_SIZE(key_blobs); i++) {
        ASSERT_EQ(
            ErrorCode::OK,
            GenerateKey(AuthorizationSetBuilder()
                            .EcdsaSigningKey(256)
                            .Digest(Digest::NONE)
                            .Authorization(TAG_NO_AUTH_REQUIRED)
                            .Authorization(TAG_MAX_USES_PER_BOOT, max_uses),
                        &key_blobs[i], &key_characteristics[i]));
    }

    for (unsigned int i = 0; i < ARR_SIZE(key_blobs) - 1; i++) {
        for (unsigned int j = 0; j < max_uses; j++)
            ASSERT_EQ(ErrorCode::OK, DefaultEcdsaSigningOperation(key_blobs[i])) <<
                "Expecting that key #" << i + 1 << " can be used for " << j + 1 << " times\n";

        ASSERT_EQ(ErrorCode::KEY_MAX_OPS_EXCEEDED, DefaultEcdsaSigningOperation(key_blobs[i])) <<
            "Expecting that key #" << i << "can not be used for " << max_uses + 1 << " times\n";
    }

    ASSERT_EQ(ErrorCode::TOO_MANY_OPERATIONS, DefaultEcdsaSigningOperation(key_blobs[KM_MAX_USE_COUNTERS]));
}

int main(int argc, char** argv) {
    using android::hardware::keymaster::V3_0::test::KeymasterHidlEnvironment;
    ::testing::AddGlobalTestEnvironment(KeymasterHidlEnvironment::Instance());
    ::testing::InitGoogleTest(&argc, argv);
    KeymasterHidlEnvironment::Instance()->init(&argc, argv);
    for (int i = 1; i < argc; ++i) {
        if (argv[i][0] == '-') {
            if (std::string(argv[i]) == "--arm_deleteAllKeys") {
                arm_deleteAllKeys = true;
            }
            if (std::string(argv[i]) == "--dump_attestations") {
                dump_Attestations = true;
            }
        }
    }
    int status = RUN_ALL_TESTS();
    ALOGI("Test result = %d", status);
    return status;
}

}  // namespace test
}  // namespace V3_0
}  // namespace keymaster
}  // namespace hardware
}  // namespace android
