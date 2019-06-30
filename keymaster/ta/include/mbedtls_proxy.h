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

#ifndef MBEDTLS_PROXY_H_
#define MBEDTLS_PROXY_H_

#include "ta_ca_defs.h"

TEE_Result mbedTLS_gen_root_cert_rsa(TEE_ObjectHandle root_rsa_key,
				      keymaster_blob_t *root_cert);

TEE_Result mbedTLS_gen_root_cert_ecc(TEE_ObjectHandle ecc_root_key,
				     keymaster_blob_t *ecc_root_cert);

TEE_Result mbedTLS_gen_attest_key_cert_rsa(TEE_ObjectHandle rsa_root_key,
						TEE_ObjectHandle rsa_attest_key,
						keymaster_cert_chain_t *cert_chain,
						keymaster_blob_t* attest_ext);

TEE_Result mbedTLS_gen_attest_key_cert_ecc(TEE_ObjectHandle ecc_root_key,
						TEE_ObjectHandle ecc_attest_key,
						keymaster_cert_chain_t *cert_chain,
						keymaster_blob_t *attest_ext);

#endif /* MBEDTLS_PROXY_H_ */
