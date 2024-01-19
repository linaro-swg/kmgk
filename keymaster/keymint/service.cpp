/*
 * Copyright 2021, The Android Open Source Project
 * Copyright 2024 BayLibre SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "android.hardware.security.keymint-service.optee"
#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/binder_process.h>

#include <optee_keymaster/OpteeKeyMintDevice.h>
#include <optee_keymaster/OpteeRemotelyProvisionedComponentDevice.h>
#include <optee_keymaster/OpteeSecureClock.h>
#include <optee_keymaster/OpteeSharedSecret.h>

using aidl::android::hardware::security::keymint::optee::OpteeKeyMintDevice;
using aidl::android::hardware::security::keymint::optee::OpteeRemotelyProvisionedComponentDevice;
using aidl::android::hardware::security::secureclock::optee::OpteeSecureClock;
using aidl::android::hardware::security::sharedsecret::optee::OpteeSharedSecret;

template <typename T, class... Args>
std::shared_ptr<T> addService(Args&&... args) {
    std::shared_ptr<T> service = ndk::SharedRefBase::make<T>(std::forward<Args>(args)...);
    auto instanceName = std::string(T::descriptor) + "/default";
    LOG(ERROR) << "Adding service instance: " << instanceName;
    auto status = AServiceManager_addService(service->asBinder().get(), instanceName.c_str());
    CHECK(status == STATUS_OK) << "Failed to add service " << instanceName;
    return service;
}

int main() {
    auto opteeKeymaster = std::make_shared<keymaster::OpteeKeymaster>();
    int err = opteeKeymaster->Initialize(keymaster::KmVersion::KEYMINT_3);
    if (err != 0) {
        LOG(FATAL) << "Could not initialize OpteeKeymaster for KeyMint (" << err << ")";
        return -1;
    }

    // Zero threads seems like a useless pool but below we'll join this thread to it, increasing
    // the pool size to 1.
    ABinderProcess_setThreadPoolMaxThreadCount(0);

    auto keyMint = addService<OpteeKeyMintDevice>(opteeKeymaster);
    auto secureClock = addService<OpteeSecureClock>(opteeKeymaster);
    auto sharedSecret = addService<OpteeSharedSecret>(opteeKeymaster);
    auto remotelyProvisionedComponent =
            addService<OpteeRemotelyProvisionedComponentDevice>(opteeKeymaster);
    ABinderProcess_joinThreadPool();
    return EXIT_FAILURE;  // should not reach
}
