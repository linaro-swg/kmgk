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

#include <android-base/logging.h>

#include "Keymaster.h"

int main(int argc, char** argv) {
    setenv("ANDROID_LOG_TAGS", "*:v", 1);
    if (getppid() == 1) {
        // If init is calling us then it's during boot and we should log to kmsg
        android::base::InitLogging(argv, &android::base::KernelLogger);
    } else {
        android::base::InitLogging(argv, &android::base::StderrLogger);
    }
    LOG(INFO) << "Waiting for OP-TEE Keymaster device";
    android::hardware::keymaster::V3_0::optee::Keymaster keymaster;
    LOG(INFO) << "OP-TEE Keymaster device ready";
    return 0;
}
