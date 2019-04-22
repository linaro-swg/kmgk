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

#ifndef OPTEE_WAIT_H
#define OPTEE_WAIT_H

#include <memory>
#include <string>
#include <utility>

#include <android-base/macros.h>
#include <keymasterV4_0/Keymaster.h>
#include <keymasterV4_0/authorization_set.h>

namespace android {
namespace hardware {
namespace keymaster {
namespace V3_0 {
namespace optee {

namespace km = ::android::hardware::keymaster::V4_0;
using KmDevice = km::support::Keymaster;

// C++ wrappers to the Keymaster hidl interface.
// This is tailored to the needs of KeyStorage, but could be extended to be
// a more general interface.

// Wrapper for a Keymaster device for methods that start a KeymasterOperation or are not
// part of one.
class Keymaster {
  public:
    Keymaster();

  private:
    std::unique_ptr<KmDevice> mDevice;
    DISALLOW_COPY_AND_ASSIGN(Keymaster);
    static bool hmacKeyGenerated;
    static uint8_t timeout;
};

}  // namespace optee
}  // namespace V3_0
}  // namespace keymaster
}  // namespace hardware
}  // namespace android

#endif /* OPTEE_WAIT_H */
