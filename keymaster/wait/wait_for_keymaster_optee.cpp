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

#include <unistd.h>

#define LOG_TAG "wait_for_keymaster_optee"
#include <android-base/logging.h>

#include <keymasterV4_0/Keymaster.h>

using android::hardware::keymaster::V4_0::SecurityLevel;
using android::hardware::keymaster::V4_0::support::Keymaster;

useconds_t kWaitTimeMicroseconds = 1000000;  // 1 second

int main(int argc, char** argv) {
    setenv("ANDROID_LOG_TAGS", "*:v", 1);
    if (getppid() == 1) {
        // If init is calling us then it's during boot and we should log to kmsg
        android::base::InitLogging(argv, &android::base::KernelLogger);
    } else {
        android::base::InitLogging(argv, &android::base::StderrLogger);
    }
    LOG(INFO) << "Waiting for Keymaster device";
    for (unsigned cycleCount = 0; cycleCount < 10 /* 10s, Not Forever */; ++cycleCount) {
        auto keymasters = Keymaster::enumerateAvailableDevices();

        bool foundOptee = false;
        bool foundTee = false;
        for (auto &dev : keymasters) {
            auto& version = dev->halVersion();
            SecurityLevel securityLevel = version.securityLevel;
            uint8_t majorVersion = version.majorVersion;

            LOG(INFO) << "Found " << version.keymasterName << " from " << version.authorName
                << " for encryption.  Security level: " << toString(securityLevel)
                << ", HAL: " << dev->descriptor() << "/" << dev->instanceName();

            std::string km_name(version.keymasterName);
            if (km_name.find("OP-TEE") != std::string::npos && majorVersion == 3) {
                foundOptee = true;
                LOG(INFO) << "OP-TEE Keymaster found";
            }
            if (securityLevel == SecurityLevel::TRUSTED_ENVIRONMENT && majorVersion == 3) {
                foundTee = true;
                LOG(INFO) << "TEE Keymaster found";
            }
        }

        if (foundTee && foundOptee) {
            LOG(INFO) << "Keymaster device ready";
            return 0;
        }
        //if (cycleCount % 10 == 1) {
            if (!foundOptee) {
                LOG(WARNING) << "Still waiting for OP-TEE Keymaster";
            }
            if (!foundTee) {
                LOG(WARNING) << "Still waiting for TEE Keymaster";
            }
        //}
        usleep(kWaitTimeMicroseconds);
    }
    LOG(INFO) << "Failed to find OP-TEE Keymaster, giving up..";
    return 1;
}
