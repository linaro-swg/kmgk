/*
**
** Copyright 2018, The Android Open Source Project
** Copyright (C) 2017 GlobalLogic
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <android-base/logging.h>
#include <android/hardware/keymaster/3.0/IKeymasterDevice.h>
#include <hidl/HidlTransportSupport.h>
#include <optee_keymaster/OpteeKeymaster.h>
#include <optee_keymaster/OpteeKeymaster3Device.h>

int main() {
    ::android::hardware::configureRpcThreadpool(1, true);
    auto opteeKeymaster = new keymaster::OpteeKeymaster();
    int err = opteeKeymaster->Initialize(keymaster::KmVersion::KEYMASTER_3);
    if (err != 0) {
        LOG(FATAL) << "Could not initialize OpteeKeymaster (" << err << ")";
        return -1;
    }

    auto keymaster = new ::keymaster::OpteeKeymaster3Device(opteeKeymaster);

    auto status = keymaster->registerAsService();
    if (status != android::OK) {
        LOG(FATAL) << "Could not register service for Keymaster 3.0 (" << status << ")";
        return -1;
    }

    android::hardware::joinRpcThreadpool();
    return -1;  // Should never get here.
}
