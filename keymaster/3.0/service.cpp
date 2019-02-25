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

#include <optee_keymaster/optee_keymaster.h>
#include <optee_keymaster/optee_keymaster3_device.h>


using android::hardware::keymaster::V3_0::IKeymasterDevice;

int main() {
    ALOGI("Loading...\n");
    ::android::hardware::configureRpcThreadpool(1, true);
    auto optee_keymaster = new keymaster::OpteeKeymaster();
    int err = optee_keymaster->Initialize();
    if (err != 0) {
        ALOGE("Could not create keymaster instance");
        return -1;
    }

    auto keymaster = new ::keymaster::OpteeKeymaster3Device(optee_keymaster);
    if (keymaster->registerAsService() != android::OK) {
        ALOGE("Could not register service for Keymaster 3.0 ");
        return 1;
    }

    android::hardware::joinRpcThreadpool();
    return -1;  // Should never get here.
}
