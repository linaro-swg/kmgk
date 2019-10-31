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

#ifndef ANDROID_OPTEE_MASTER_CRYPTO_H
#define ANDROID_OPTEE_MASTER_CRYPTO_H

#define KEY_LENGTH 16
#define TAG_LENGTH 16
#define IV_LENGTH 12

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "ta_ca_defs.h"
#include "paddings.h"

TEE_Result TA_open_secret_key(TEE_ObjectHandle *secretKey);

TEE_Result TA_create_secret_key(void);

TEE_Result TA_execute(uint8_t *data, const size_t size, const uint32_t mode);
TEE_Result TA_encrypt(uint8_t *data, const size_t size);
TEE_Result TA_decrypt(uint8_t *data, const size_t size);

void TA_free_master_key(void);

#endif/* ANDROID_OPTEE_MASTER_CRYPTO_H */
