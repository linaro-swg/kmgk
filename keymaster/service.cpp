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

#define LOG_TAG "android.hardware.keymaster@3.0-service.optee"

#include <android/hardware/keymaster/3.0/IKeymasterDevice.h>

#include <hidl/HidlTransportSupport.h>
#include <hidl/LegacySupport.h>
#include <utils/Log.h>

#include "optee_keymaster.h"

using android::hardware::configureRpcThreadpool;
using android::hardware::joinRpcThreadpool;
using android::hardware::keymaster::V3_0::IKeymasterDevice;
using android::hardware::keymaster::V3_0::optee::OpteeKeymasterDevice;
using ::android::OK;
using ::android::sp;

const uint32_t max_threads = 1;

int main() {
    ALOGI("Loading...\n");
    sp<IKeymasterDevice> keymaster = new (std::nothrow) OpteeKeymasterDevice;
    if (keymaster == nullptr) {
        ALOGE("Could not create keymaster instance");
        return 1;
    }
    configureRpcThreadpool(max_threads, true);
    if (keymaster->registerAsService() != OK) {
        ALOGE("Could not register service.");
        return 1;
    }
    joinRpcThreadpool();

    return 0;
}
