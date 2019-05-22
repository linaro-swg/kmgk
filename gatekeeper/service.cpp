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

#define LOG_TAG "android.hardware.gatekeeper@1.0-service.optee"

#include <android/hardware/gatekeeper/1.0/IGatekeeper.h>

#include <hidl/HidlTransportSupport.h>
#include <hidl/LegacySupport.h>
#include <utils/Log.h>

#include "optee_gatekeeper_device.h"

using android::hardware::configureRpcThreadpool;
using android::hardware::joinRpcThreadpool;
using android::hardware::gatekeeper::V1_0::IGatekeeper;
using android::hardware::gatekeeper::V1_0::optee::OpteeGateKeeperDevice;
using ::android::OK;
using ::android::sp;

const uint32_t max_threads = 1;

int main() {
    ALOGD("Checking gk connection to optee_os");
    OpteeGateKeeperDevice *gk = new (std::nothrow) OpteeGateKeeperDevice;
    if (!gk->getConnected()) {
        ALOGE("gatekeeper failed to connect to optee_os");
        return 1;
    }

    ALOGI("Loading...");
    sp<IGatekeeper> gatekeeper = gk;
    if (gatekeeper == nullptr) {
        ALOGE("Could not create gatekeeper instance");
        return 1;
    }
    configureRpcThreadpool(max_threads, true);
    if (gatekeeper->registerAsService() != OK) {
        ALOGE("Could not register service.");
        return 1;
    }
    joinRpcThreadpool();

    return 0; // should never get here
}
