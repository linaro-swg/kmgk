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

#include <string>
#include <utils/Log.h>

#include <gatekeeper_ipc.h>
#include "optee_gatekeeper_device.h"

#undef LOG_TAG
#define LOG_TAG "OpteeGateKeeper"

namespace android {
namespace hardware {
namespace gatekeeper {
namespace V1_0 {
namespace optee {

OpteeGateKeeperDevice::OpteeGateKeeperDevice()
    : connected_(false)
{
    initialize();
    connect();
}

OpteeGateKeeperDevice::~OpteeGateKeeperDevice()
{
    disconnect();
    finalize();
}

bool OpteeGateKeeperDevice::getConnected() {
    ALOGD("%s %d connected_ = %d", __func__, __LINE__, connected_);
    return connected_;
}

Return<void> OpteeGateKeeperDevice::enroll(uint32_t uid,
        const hidl_vec<uint8_t>& currentPasswordHandle,
        const hidl_vec<uint8_t>& currentPassword,
        const hidl_vec<uint8_t>& desiredPassword,
        enroll_cb cb)
{
    ALOGV("Start enroll");
    GatekeeperResponse rsp;

    if (!connected_) {
        ALOGE("Device is not connected");
        rsp.code = GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
        cb(rsp);
        return Void();
    }

    if (desiredPassword.size() == 0) {
        ALOGE("Can't enroll new password with zero length");
        rsp.code = GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
        cb(rsp);
        return Void();
    }

    /*
     * Enroll request layout
     * +--------------------------------+---------------------------------+
     * | Name                           | Number of bytes                 |
     * +--------------------------------+---------------------------------+
     * | uid                            | 4                               |
     * | desired_password_length        | 4                               |
     * | desired_password               | #desired_password_length        |
     * | current_password_length        | 4                               |
     * | current_password               | #current_password_length        |
     * | current_password_handle_length | 4                               |
     * | current_password_handle        | #current_password_handle_length |
     * +--------------------------------+---------------------------------+
     */
    const uint32_t request_size = sizeof(uid) +
        sizeof(desiredPassword.size()) +
        desiredPassword.size() +
        sizeof(currentPassword.size()) +
        currentPassword.size() +
        sizeof(currentPasswordHandle.size()) +
        currentPasswordHandle.size();
    uint8_t request[request_size];

    uint8_t *i_req = request;
    serialize_int(&i_req, uid);
    serialize_blob(&i_req, desiredPassword.data(), desiredPassword.size());
    serialize_blob(&i_req, currentPassword.data(), currentPassword.size());
    serialize_blob(&i_req, currentPasswordHandle.data(),
            currentPasswordHandle.size());

    uint32_t response_size = RECV_BUF_SIZE;
    uint8_t response[response_size];

    if(!Send(GK_ENROLL, request, request_size, response, response_size)) {
        ALOGE("Enroll failed without respond");
        rsp.code = GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
        cb(rsp);
        return Void();
    }

    const uint8_t *i_resp = response;
    uint32_t error;

    /*
     * Enroll response layout
     * +--------------------------------+---------------------------------+
     * | Name                           | Number of bytes                 |
     * +--------------------------------+---------------------------------+
     * | error                          | 4                               |
     * +--------------------------------+---------------------------------+
     * | retry_timeout                  | 4                               |
     * +------------------------------ OR --------------------------------+
     * | response_handle_length         | 4                               |
     * | response_handle                | #response_handle_length         |
     * +--------------------------------+---------------------------------+
     */
    deserialize_int(&i_resp, &error);
    if (error == ERROR_RETRY) {
        uint32_t retry_timeout;
        deserialize_int(&i_resp, &retry_timeout);
        ALOGV("Enroll returns retry timeout %u", retry_timeout);
        rsp.timeout = retry_timeout;
        rsp.code = GatekeeperStatusCode::ERROR_RETRY_TIMEOUT;
        cb(rsp);
        return Void();
    }

    if (error != ERROR_NONE) {
        ALOGE("Enroll failed");
        rsp.code = GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
        cb(rsp);
        return Void();
    }

    const uint8_t *response_handle = nullptr;
    uint32_t response_handle_length = 0;

    deserialize_blob(&i_resp, &response_handle, &response_handle_length);

    std::unique_ptr<uint8_t []> response_handle_ret(
            new (std::nothrow) uint8_t[response_handle_length]);
    if (!response_handle_ret) {
        ALOGE("Cannot create enrolled password handle, not enough memory");
        rsp.code = GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
        cb(rsp);
        return Void();
    }

    memcpy(response_handle_ret.get(), response_handle, response_handle_length);

    rsp.data.setToExternal(response_handle_ret.release(),
                           response_handle_length,
                           true);
    rsp.code = GatekeeperStatusCode::STATUS_OK;

    ALOGV("Enroll returns success");

    cb(rsp);
    return Void();
}

Return<void> OpteeGateKeeperDevice::verify(uint32_t uid,
                                uint64_t challenge,
                                const hidl_vec<uint8_t>& enrolledPasswordHandle,
                                const hidl_vec<uint8_t>& providedPassword,
                                verify_cb cb)
{
    ALOGV("Start verify");
    GatekeeperResponse rsp;

    if (!connected_) {
        ALOGE("Device is not connected");
        rsp.code = GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
        cb(rsp);
        return Void();
    }

    /*
     * Verify request layout
     * +---------------------------------+----------------------------------+
     * | Name                            | Number of bytes                  |
     * +---------------------------------+----------------------------------+
     * | uid                             | 4                                |
     * | challenge                       | 8                                |
     * | enrolled_password_handle_length | 4                                |
     * | enrolled_password_handle        | #enrolled_password_handle_length |
     * | provided_password_length        | 4                                |
     * | provided_password               | #provided_password_length        |
     * +---------------------------------+----------------------------------+
     */
    const uint32_t request_size = sizeof(uid) +
        sizeof(challenge) +
        sizeof(enrolledPasswordHandle.size()) +
        enrolledPasswordHandle.size() +
        sizeof(providedPassword.size()) +
        providedPassword.size();
    uint8_t request[request_size];

    uint8_t *i_req = request;
    serialize_int(&i_req, uid);
    serialize_int64(&i_req, challenge);
    serialize_blob(&i_req, enrolledPasswordHandle.data(),
            enrolledPasswordHandle.size());
    serialize_blob(&i_req, providedPassword.data(), providedPassword.size());

    uint32_t response_size = RECV_BUF_SIZE;
    uint8_t response[response_size];

    if(!Send(GK_VERIFY, request, request_size, response, response_size)) {
        ALOGE("Verify failed without respond");
        rsp.code = GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
        cb(rsp);
        return Void();
    }

    const uint8_t *i_resp = response;
    uint32_t error;

    /*
     * Verify response layout
     * +--------------------------------+---------------------------------+
     * | Name                           | Number of bytes                 |
     * +--------------------------------+---------------------------------+
     * | error                          | 4                               |
     * +--------------------------------+---------------------------------+
     * | retry_timeout                  | 4                               |
     * +------------------------------ OR --------------------------------+
     * | response_auth_token_length     | 4                               |
     * | response_auth_token            | #response_handle_length         |
     * | response_request_reenroll      | 4                               |
     * +--------------------------------+---------------------------------+
     */
    deserialize_int(&i_resp, &error);
    if (error == ERROR_RETRY) {
        uint32_t retry_timeout;
        deserialize_int(&i_resp, &retry_timeout);
        ALOGV("Verify returns retry timeout %u", retry_timeout);
        rsp.timeout = retry_timeout;
        rsp.code = GatekeeperStatusCode::ERROR_RETRY_TIMEOUT;
        cb(rsp);
        return Void();
    } else if (error != ERROR_NONE) {
        ALOGE("Verify failed");
        rsp.code = GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
        cb(rsp);
        return Void();
    }

    const uint8_t *response_auth_token = nullptr;
    uint32_t response_auth_token_length = 0;

    deserialize_blob(&i_resp, &response_auth_token,
        &response_auth_token_length);

    std::unique_ptr<uint8_t []> auth_token_ret(
            new (std::nothrow) uint8_t[response_auth_token_length]);
    if (!auth_token_ret) {
        ALOGE("Cannot create auth token, not enough memory");
        rsp.code = GatekeeperStatusCode::ERROR_GENERAL_FAILURE;
        cb(rsp);
        return Void();
    }

    memcpy(auth_token_ret.get(), response_auth_token,
            response_auth_token_length);
    rsp.data.setToExternal(auth_token_ret.release(),
                           response_auth_token_length,
                           true);

    uint32_t response_request_reenroll;
    deserialize_int(&i_resp, &response_request_reenroll);

    if (response_request_reenroll != 0) {
        rsp.code = GatekeeperStatusCode::STATUS_REENROLL;
    } else {
        rsp.code = GatekeeperStatusCode::STATUS_OK;
    }

    ALOGV("Verify returns success");

    cb(rsp);
    return Void();
}

Return<void> OpteeGateKeeperDevice::deleteUser(uint32_t uid, deleteUser_cb cb)
{
    GatekeeperResponse rsp;
    (void)uid;
    rsp.code = GatekeeperStatusCode::ERROR_NOT_IMPLEMENTED;
    cb(rsp);
    return Void();
}

Return<void> OpteeGateKeeperDevice::deleteAllUsers(deleteAllUsers_cb cb)
{
    GatekeeperResponse rsp;
    rsp.code = GatekeeperStatusCode::ERROR_NOT_IMPLEMENTED;
    cb(rsp);
    return Void();
}

bool OpteeGateKeeperDevice::initialize()
{
    if (!gatekeeperIPC_.initialize()) {
        ALOGE("Fail to connect to TEE");
        return false;
    }

    return true;
}

bool OpteeGateKeeperDevice::connect()
{
    if (connected_) {
        ALOGE("Device is already connected");
        return false;
    }

    if (!gatekeeperIPC_.connect(TA_GATEKEEPER_UUID)) {
        ALOGE("Fail to load Gatekeeper TA");
        return false;
    }
    connected_ = true;

    ALOGV("Connected");

    return true;
}

void OpteeGateKeeperDevice::disconnect()
{
    if (connected_) {
        gatekeeperIPC_.disconnect();
        connected_ = false;
    }

    ALOGV("Disconnected");
}

void OpteeGateKeeperDevice::finalize()
{
    gatekeeperIPC_.finalize();
}

bool OpteeGateKeeperDevice::Send(uint32_t command,
        const uint8_t *request, uint32_t request_size,
        uint8_t *response, uint32_t& response_size)
{
    return gatekeeperIPC_.call(command, request, request_size,
            response, response_size);
}

}  // namespace optee
}  // namespace V1_0
}  // namespace gatekeeper
}  // namespace hardware
}  // namespace android