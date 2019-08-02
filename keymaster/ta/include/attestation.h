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

#ifndef ATTESTATION_H_
#define ATTESTATION_H_

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "mbedtls_proxy.h"
#include "ta_ca_defs.h"

#define EMPTY_BLOB {.data = NULL, .data_length = 0}

//#define ENUM_PERS_OBJS //only for testing
//#define WIPE_PERS_OBJS //only for testing

#define RSA_KEY_SIZE 1024U
#define EC_KEY_SIZE 256U

#define RSA_MAX_KEY_SIZE 4096U
#define EC_MAX_KEY_SIZE 521U

#define RSA_KEY_BUFFER_SIZE (RSA_KEY_SIZE / 8)
#define EC_KEY_BUFFER_SIZE (EC_KEY_SIZE / 8)

#define RSA_MAX_KEY_BUFFER_SIZE (RSA_MAX_KEY_SIZE / 8)
#define EC_MAX_KEY_BUFFER_SIZE (EC_MAX_KEY_SIZE / 8 + 1)

#define ROOT_CERT_BUFFER_SIZE 4096U
#define ATTEST_CERT_BUFFER_SIZE 4096U

#define UNIQUE_ID_BUFFER_SIZE 16U

#define ROOT_ATT_CERT_INDEX 1U
#define KEY_ATT_CERT_INDEX 0U

#ifdef ENUM_PERS_OBJS
void TA_enum_attest_objs(void);
#endif

#ifdef WIPE_PERS_OBJS
void TA_wipe_attest_objs(void);
#endif

TEE_Result TA_open_rsa_attest_key(TEE_ObjectHandle *rsaKey);
TEE_Result TA_open_ec_attest_key(TEE_ObjectHandle *ecKey);
TEE_Result TA_open_root_rsa_attest_cert(TEE_ObjectHandle *attCert);
TEE_Result TA_open_root_ec_attest_cert(TEE_ObjectHandle *attCert);

#ifdef CFG_ATTESTATION_PROVISIONING
keymaster_error_t TA_SetAttestationKey(TEE_TASessionHandle sessionSTA, TEE_Param params[TEE_NUM_PARAMS]);
keymaster_error_t TA_AppendAttestationCertKey(TEE_Param params[TEE_NUM_PARAMS]);
#endif

keymaster_error_t TA_read_root_attest_cert(uint32_t type,
		keymaster_cert_chain_t *cert_chain);
TEE_Result TA_gen_key_attest_cert(TEE_TASessionHandle sessionSTA,
		uint32_t type, TEE_ObjectHandle attestedKey,
		keymaster_key_param_set_t *attest_params,
		keymaster_key_characteristics_t *key_chr,
		keymaster_cert_chain_t *cert_chain,
		uint8_t verified_boot);

TEE_Result TA_create_attest_objs(TEE_TASessionHandle sessionSTA);

void TA_close_attest_obj(TEE_ObjectHandle attObj);

TEE_Result TA_write_attest_cert(TEE_ObjectHandle attObj,
		const uint8_t *buffer, const size_t buffSize);
TEE_Result TA_read_attest_cert(TEE_ObjectHandle attObj,
						keymaster_cert_chain_t *cert_chain);

TEE_Result TA_generate_UniqueID(uint64_t T, uint8_t *appID,uint32_t appIDlen,
		uint8_t R, uint8_t *uniqueID, uint32_t *uniqueIDlen);

#endif /* ATTESTATION_H_ */
