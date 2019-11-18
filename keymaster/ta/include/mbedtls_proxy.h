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

keymaster_error_t mbedTLS_decode_pkcs8(keymaster_blob_t key_data,
				       TEE_Attribute **attrs,
				       uint32_t *attrs_count,
				       const keymaster_algorithm_t algorithm,
				       uint32_t *key_size,
				       uint64_t *rsa_public_exponent);

keymaster_error_t mbedTLS_encode_key(keymaster_blob_t *export_data,
                                     const uint32_t type,
                                     const TEE_ObjectHandle *obj_h);

// TODO: have a comment here saying something about the RSA
// algorithm/schema in use or if there are any limitations. I.e, a
// general description of what kind of root cert it generates.
TEE_Result mbedTLS_gen_root_cert_rsa(TEE_ObjectHandle root_rsa_key,
				      keymaster_blob_t *root_cert);

TEE_Result mbedTLS_gen_root_cert_ecc(TEE_ObjectHandle ecc_root_key,
				     keymaster_blob_t *ecc_root_cert);

TEE_Result mbedTLS_gen_attest_key_cert(TEE_ObjectHandle root_key,
				       TEE_ObjectHandle attest_key,
				       keymaster_algorithm_t alg,
				       unsigned int key_usage,
				       keymaster_cert_chain_t *cert_chain,
				       keymaster_blob_t *attest_ext);

keymaster_error_t mbedTLS_encode_ec_sign(uint8_t *out, uint32_t *out_l);

keymaster_error_t mbedTLS_decode_ec_sign(keymaster_blob_t *sig,
					 uint32_t key_size);

#endif /* MBEDTLS_PROXY_H_ */
