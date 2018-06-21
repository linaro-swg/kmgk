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

#ifndef TA_GATEKEEPER_H
#define TA_GATEKEEPER_H

#include <stdint.h>
#include <compiler.h>

/*
 * Please keep password_handle_t structure consistent with its counterpart
 * which defined in system/gatekeeper/include/gatekeeper/password_handle.h
 */

#define HANDLE_VERSION 2
#define HANDLE_VERSION_THROTTLE 2
#define HANDLE_FLAG_THROTTLE_SECURE 1

typedef uint64_t secure_id_t;
typedef uint64_t salt_t;

typedef struct __packed {
	uint8_t version;
	secure_id_t user_id;
	uint64_t flags;

	salt_t salt;
	uint8_t signature[32];

	bool hardware_backed;
} password_handle_t;


/*
 * Please keep hw_auth_token_t structure consistent with its counterpart
 * which defined in hardware/libhardware/include/hardware/hw_auth_token.h
 */

#define HW_AUTH_TOKEN_VERSION 0

typedef enum {
	HW_AUTH_NONE = 0,
	HW_AUTH_PASSWORD = 1 << 0,
	HW_AUTH_FINGERPRINT = 1 << 1,
	// Additional entries should be powers of 2.
	HW_AUTH_ANY = (int)((uint32_t) ~0U)
} hw_authenticator_type_t;

/*
 * Data format for an authentication record used to prove successful authentication.
 */
typedef struct __packed {
	uint8_t version;
	uint64_t challenge;
	uint64_t user_id;             // secure user ID, not Android user ID
	uint64_t authenticator_id;    // secure authenticator ID
	uint32_t authenticator_type;  // hw_authenticator_type_t, in network order
	uint64_t timestamp;           // in network order
	uint8_t hmac[32];
} hw_auth_token_t;


#define HMAC_SHA256_KEY_SIZE_BYTE 32
#define HMAC_SHA256_KEY_SIZE_BIT (8*HMAC_SHA256_KEY_SIZE_BYTE)


#define TEE_TRUE TEE_SUCCESS
#define TEE_FALSE 1

/*
 * Please keep this variable consistent with TA_UUID variable that
 * is defined in Keymaster Android.mk file
 */
#define TA_KEYMASTER_UUID { 0xdba51a17, 0x0563, 0x11e7, \
	                { 0x93, 0xb1, 0x6f, 0xa7, 0xb0, 0x07, 0x1a, 0x51} }

/*
 * Please keep this define consistent with KM_GET_AUTHTOKEN_KEY constant that
 * is defined in Keymaster
 */
#define KM_GET_AUTHTOKEN_KEY 65536

#endif /* TA_GATEKEEPER_H */
