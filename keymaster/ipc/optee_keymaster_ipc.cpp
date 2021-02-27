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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <log/log.h>
#include <tee_client_api.h>
#include <hardware/keymaster2.h>

#include <optee_keymaster/ipc/optee_keymaster_ipc.h>

#undef LOG_TAG
#define LOG_TAG "OpteeKeymaster_ipc"

static TEEC_Context ctx;
static TEEC_Session sess;
static bool connected = false;

int optee_keymaster_initialize(void) {
    TEEC_Result res;

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        ALOGE("TEEC_InitializeContext failed with code 0x%x", res);
        return (int)res;
    }

    return 0;
}

int optee_keymaster_connect(void) {
    TEEC_Result res;
    TEEC_UUID uuid = TA_KEYMASTER_UUID;
    uint32_t err_origin;

    if (connected) {
        ALOGE("Connection with trustled application already established");
        return false;
    }

    /* Open a session to the TA */
    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC,
            NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        ALOGE("TEEC_Opensession failed with code 0x%x origin 0x%x",
                res, err_origin);
        return (int)res;
    }
    connected = true;
    ALOGI("Connection with keystore was established");
    return 0;
}

void optee_keymaster_disconnect(void) {
    TEEC_CloseSession(&sess);
    connected  = false;
}

void optee_keymaster_finalize(void) {
    TEEC_FinalizeContext(&ctx);
}

const char* keymaster_error_message(uint32_t error) {
    switch((int)error) {
        case (KM_ERROR_OK):
            return "No error";
        case (KM_ERROR_UNSUPPORTED_PURPOSE):
            return "Purpose is unsupported";
        case (KM_ERROR_INCOMPATIBLE_PURPOSE):
            return "Purpose is incompatible";
        case (KM_ERROR_UNSUPPORTED_ALGORITHM):
            return "Algorithm is unsupported";
        case (KM_ERROR_INCOMPATIBLE_ALGORITHM):
            return "Algorithm is incompatible";
        case (KM_ERROR_UNSUPPORTED_KEY_SIZE):
            return "Unsupported key size";
        case (KM_ERROR_UNSUPPORTED_BLOCK_MODE):
            return "Block mode is unsupported";
        case (KM_ERROR_INCOMPATIBLE_BLOCK_MODE):
            return "Block mode is incompatible";
        case (KM_ERROR_UNSUPPORTED_MAC_LENGTH):
            return "Mac length is unsupported";
        case (KM_ERROR_UNSUPPORTED_PADDING_MODE):
            return "Padding mode is unsupported";
        case (KM_ERROR_INCOMPATIBLE_PADDING_MODE):
            return "Padding mode is incompatible";
        case (KM_ERROR_UNSUPPORTED_DIGEST):
            return "Digest is unsupported";
        case (KM_ERROR_INCOMPATIBLE_DIGEST):
            return "Digest id incompatible";
        case (KM_ERROR_INVALID_USER_ID):
            return "User ID is invalid";
        case (KM_ERROR_INVALID_AUTHORIZATION_TIMEOUT):
            return "Invalid authorization timeout";
        case (KM_ERROR_UNSUPPORTED_KEY_FORMAT):
            return "Key format is unsupported";
        case (KM_ERROR_INCOMPATIBLE_KEY_FORMAT):
            return "Key format is incompatible";
        case (KM_ERROR_INVALID_INPUT_LENGTH):
            return "Invalid input length";
        case (KM_ERROR_KEY_EXPORT_OPTIONS_INVALID):
            return "Key export options invalid";
        case (KM_ERROR_KEY_USER_NOT_AUTHENTICATED):
            return "User is not authenticated";
        case (KM_ERROR_INVALID_OPERATION_HANDLE):
            return "Operation handle is invalid";
        case (KM_ERROR_INSUFFICIENT_BUFFER_SPACE):
            return "Insufficient buffer space";
        case (KM_ERROR_VERIFICATION_FAILED):
            return "Verification failed";
        case (KM_ERROR_TOO_MANY_OPERATIONS):
            return "Too many operations";
        case (KM_ERROR_INVALID_KEY_BLOB):
            return "Key blob is invalid";
        case (KM_ERROR_IMPORTED_KEY_NOT_ENCRYPTED):
            return "Imported key is not encrypted";
        case (KM_ERROR_IMPORTED_KEY_DECRYPTION_FAILED):
            return "Imported key decryption failed";
        case (KM_ERROR_IMPORTED_KEY_NOT_SIGNED):
            return "Imported key is not signed";
        case (KM_ERROR_IMPORTED_KEY_VERIFICATION_FAILED):
            return "Imported key verification failed";
        case (KM_ERROR_INVALID_ARGUMENT):
            return "Invalid argument";
        case (KM_ERROR_UNSUPPORTED_TAG):
            return "Unsupported tag";
        case (KM_ERROR_INVALID_TAG):
            return "Invalid tag";
        case (KM_ERROR_MEMORY_ALLOCATION_FAILED):
            return "memory allocation failed";
        case (KM_ERROR_IMPORT_PARAMETER_MISMATCH):
            return "Import parameters mismatch";
        case (KM_ERROR_SECURE_HW_ACCESS_DENIED):
            return "Secure hardware access denied";
        case (KM_ERROR_OPERATION_CANCELLED):
            return "Operation was cancelled";
        case (KM_ERROR_CONCURRENT_ACCESS_CONFLICT):
            return "Concurent access conflict";
        case (KM_ERROR_SECURE_HW_BUSY):
            return "Secure harware is busy";
        case (KM_ERROR_SECURE_HW_COMMUNICATION_FAILED):
            return "Secure hardware communication failed";
        case (KM_ERROR_UNSUPPORTED_EC_FIELD):
            return "Unsupported EC field";
        case (KM_ERROR_MISSING_NONCE):
            return "Missing nonce";
        case (KM_ERROR_INVALID_NONCE):
            return "Nonce is invalid";
        case (KM_ERROR_MISSING_MAC_LENGTH):
            return "Mac length is missing";
        case (KM_ERROR_KEY_RATE_LIMIT_EXCEEDED):
            return "Key rate limit has been exceeded";
        case (KM_ERROR_CALLER_NONCE_PROHIBITED):
            return "Caller nonce is prohibited";
        case (KM_ERROR_KEY_MAX_OPS_EXCEEDED):
            return "Key max operations has been exceeded";
        case (KM_ERROR_INVALID_MAC_LENGTH):
            return "Mac length is invalid";
        case (KM_ERROR_MISSING_MIN_MAC_LENGTH):
            return "Min mac length is missing";
        case (KM_ERROR_UNSUPPORTED_MIN_MAC_LENGTH):
            return "Min mac length is unsupported";
        case (KM_ERROR_UNSUPPORTED_EC_CURVE):
            return "Unsupported EC curve";
        case (KM_ERROR_KEY_REQUIRES_UPGRADE):
            return "Key requeres upgrade";
        case (KM_ERROR_ATTESTATION_CHALLENGE_MISSING):
            return "Attestation challenge missing";
        case (KM_ERROR_ATTESTATION_APPLICATION_ID_MISSING):
            return "Attestation application ID missing";
        case (KM_ERROR_KEYMASTER_NOT_CONFIGURED):
            return "Keymaster is not configured";
        case (KM_ERROR_UNIMPLEMENTED):
            return "Feature is not implemented";
        case (KM_ERROR_VERSION_MISMATCH):
            return "Version mismatch";
        default:
            return "Unknown error";
    }
}

keymaster_error_t optee_keymaster_call(uint32_t cmd,
				       const keymaster::Serializable& req,
				       keymaster::KeymasterResponse* rsp) {
    TEEC_Operation op;
    uint32_t res;
    uint32_t err_origin;

    ALOGD("%s %d %u\n", __func__, __LINE__, cmd);
    if (!connected) {
	ALOGE("Keystore trusted application is not connected");
	return KM_ERROR_SECURE_HW_COMMUNICATION_FAILED;
    }

    (void)memset(&op, 0, sizeof(op));

    uint32_t req_size = req.SerializedSize();
    if (req_size > OPTEE_KEYMASTER_SEND_BUF_SIZE) {
	ALOGE("Request too big: %u Max size: %u", req_size,
	      OPTEE_KEYMASTER_SEND_BUF_SIZE);
	return KM_ERROR_INVALID_INPUT_LENGTH;
    }

    uint8_t send_buf[OPTEE_KEYMASTER_SEND_BUF_SIZE];
    keymaster::Eraser send_buf_eraser(send_buf, OPTEE_KEYMASTER_SEND_BUF_SIZE);
    req.Serialize(send_buf, send_buf + req_size);

    /* Send it */
    uint8_t recv_buf[OPTEE_KEYMASTER_RECV_BUF_SIZE];
    keymaster::Eraser recv_buf_eraser(recv_buf, OPTEE_KEYMASTER_RECV_BUF_SIZE);
    uint32_t rsp_size = OPTEE_KEYMASTER_RECV_BUF_SIZE;
    op.paramTypes = (uint32_t)TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					       TEEC_MEMREF_TEMP_OUTPUT,
					       TEEC_NONE,
					       TEEC_NONE);
	op.params[0].tmpref.buffer = (void*)send_buf;
	op.params[0].tmpref.size   = req_size;
	op.params[1].tmpref.buffer = (void*)recv_buf;
	op.params[1].tmpref.size   = rsp_size;

    res = TEEC_InvokeCommand(&sess, cmd, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
	ALOGI("TEEC_InvokeCommand cmd %d failed with code 0x%08x (%s) origin "
	      "0x%08x", cmd, res, keymaster_error_message(res), err_origin);
	if (res == TEEC_ERROR_TARGET_DEAD) {
		optee_keymaster_disconnect();
		optee_keymaster_connect();
	}
    }

    const uint8_t* p = recv_buf;
    if (!rsp->Deserialize(&p, p + rsp_size)) {
	ALOGE("Error deserializing response of size %d\n", (int)rsp_size);
	return KM_ERROR_UNKNOWN_ERROR;
    } else if (rsp->error != KM_ERROR_OK) {
	ALOGE("Response of size %d contained error code %d\n", (int)rsp_size,
	      (int)rsp->error);
    } else if (res != KM_ERROR_OK) {
	/*
	 * rsp->error is KM_ERROR_OK but res isn't? The only time this happens
	 * is in the case of param_types != exp_param_types in
	 * TA_InvokeCommandEntryPoint() so res can't be serialized into rsp.
	 */
	ALOGE("Response of size %d contained error code %d\n", (int)rsp_size,
	      (int)res);
	return (keymaster_error_t)res;
    }

    return rsp->error;
}
