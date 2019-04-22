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

#include <iostream>

#include "Keymaster.h"

#include <android-base/logging.h>
#include <keymasterV4_0/authorization_set.h>
#include <keymasterV4_0/keymaster_utils.h>

#undef LOG_TAG
#define LOG_TAG "OpteeKeymaster_wait"

namespace android {
namespace hardware {
namespace keymaster {
namespace V3_0 {
namespace optee {

using ::std::string;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::keymaster::V4_0::SecurityLevel;

/* static */ bool Keymaster::hmacKeyGenerated = false;
/* static */ uint8_t Keymaster::timeout = 0;

Keymaster::Keymaster() {
    auto devices = KmDevice::enumerateAvailableDevices();
    if (!hmacKeyGenerated) {
        KmDevice::performHmacKeyAgreement(devices);
        hmacKeyGenerated = true;
    }
    for (auto& dev : devices) {
        // Do not use StrongBox for device encryption / credential encryption.  If a security chip
        // is present it will have Weaver, which already strengthens CE.  We get no additional
        // benefit from using StrongBox here, so skip it.
        if (dev->halVersion().securityLevel != SecurityLevel::STRONGBOX) {
            mDevice = std::move(dev);
            break;
        }
    }
    if (!mDevice) return;
    auto& version = mDevice->halVersion();
    LOG(INFO) << "Using " << version.keymasterName << " from " << version.authorName
              << " for encryption.  Security level: " << toString(version.securityLevel)
              << ", HAL: " << mDevice->descriptor() << "/" << mDevice->instanceName();

    std::string km_name(version.keymasterName);
    if((km_name.find("OP-TEE")) != std::string::npos) {
        LOG(INFO) << "OP-TEE Keymaster service ready!";
    }
    else {
        if (timeout > 100) {
            LOG(INFO) << "Failed to detect OP-TEE Keymaster, giving up..";
        }
        else {
            if (timeout % 10 == 0)
                LOG(INFO) << "OP-TEE Keymaster not ready, keep waiting.. " << unsigned(timeout);
            timeout++;
            Keymaster();
        }
    }
}

}  // namespace optee
}  // namespace V3_0
}  // namespace keymaster
}  // namespace hardware
}  // namespace android