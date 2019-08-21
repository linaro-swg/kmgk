/*
 *
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

#ifndef OPTEE_GATEKEEPER_H
#define OPTEE_GATEKEEPER_H

#include <android/hardware/gatekeeper/1.0/IGatekeeper.h>
#include <hidl/Status.h>

#include <hidl/MQDescriptor.h>

#include <hardware/hardware.h>

#include "optee_ipc.h"

namespace android {
namespace hardware {
namespace gatekeeper {
namespace V1_0 {
namespace optee {

using android::hardware::gatekeeper::V1_0::GatekeeperResponse;
using android::hardware::gatekeeper::V1_0::IGatekeeper;
using android::hardware::Return;
using android::hardware::Void;
using android::hardware::hidl_vec;
using android::hardware::hidl_string;
using android::sp;

class OpteeGateKeeperDevice : public IGatekeeper
{
public:
    OpteeGateKeeperDevice();
    ~OpteeGateKeeperDevice();
    bool getConnected();

    // Methods from ::android::hardware::gatekeeper::V1_0::IGatekeeper follow.
    Return<void> enroll(uint32_t uid,
                        const hidl_vec<uint8_t>& currentPasswordHandle,
                        const hidl_vec<uint8_t>& currentPassword,
                        const hidl_vec<uint8_t>& desiredPassword,
                        enroll_cb _hidl_cb)  override;
    Return<void> verify(uint32_t uid,
                        uint64_t challenge,
                        const hidl_vec<uint8_t>& enrolledPasswordHandle,
                        const hidl_vec<uint8_t>& providedPassword,
                        verify_cb _hidl_cb)  override;
    Return<void> deleteUser(uint32_t uid, deleteUser_cb _hidl_cb)  override;
    Return<void> deleteAllUsers(deleteAllUsers_cb _hidl_cb)  override;
private:
    bool initialize();
    bool connect();
    void disconnect();
    void finalize();

    bool Send(uint32_t command, const uint8_t *request, uint32_t request_size,
                           uint8_t *response, uint32_t& response_size);

    OpteeIPC gatekeeperIPC_;
    bool connected_;
};

}  // namespace optee
}  // namespace V1_0
}  // namespace gatekeeper
}  // namespace hardware
}  // namespace android

#endif /* OPTEE_GATEKEEPER_H */
