// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2018, Linaro Limited */

#include <attestation.h>
#include <generator.h>

#include <mbedtls/aes.h>
#include <mbedtls/base64.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/des.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md5.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/x509.h>


#define CERT_ROOT_ORG "Android"
#define CERT_ROOT_ORG_UNIT_RSA "Attestation RSA root CA"
#define CERT_ROOT_ORG_UNIT_ECC "Attestation ECC root CA"
#define CERT_ROOT_MAX_SIZE 4096

#define MBEDTLS_OID_ATTESTATION "\x2B\x06\x01\x04\x01\xD6\x79\x02\x01\x11"

const char *cert_root_subject_rsa = "OU=" CERT_ROOT_ORG_UNIT_RSA
			       ",O=" CERT_ROOT_ORG
			       ",CN=" CERT_ROOT_ORG;

const char *cert_root_subject_ecc = "OU=" CERT_ROOT_ORG_UNIT_ECC
			       ",O=" CERT_ROOT_ORG
			       ",CN=" CERT_ROOT_ORG;
const char *cert_attest_key_subject = "CN=Android Keystore Key";

const uint32_t cert_version = 2;	/* x509 version of cert. v3 used. */
const uint32_t cert_version_tag;	/* tag value for version field. */
const uint32_t cert_serial_number = 1;	/* serialNumber of cert. */

/* entropy source */
static int f_rng(void *rng __unused, unsigned char *output, size_t output_len)
{
	TEE_GenerateRandom(output, output_len);
	return 0;
}

/* create mbedtls_pk_context based on ECC key attributes */
static TEE_Result mbedTLS_import_ecc_pk(mbedtls_pk_context *pk,
					const TEE_ObjectHandle key_obj)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectInfo obj_info;
	uint32_t read_size = 0;
	uint8_t key_attr_buf[EC_MAX_KEY_BUFFER_SIZE] = {0};
	uint32_t key_attr_buf_size = EC_MAX_KEY_BUFFER_SIZE;
	const uint32_t attr_ids[KM_ATTR_COUNT_EC] = { TEE_ATTR_ECC_PRIVATE_VALUE,
						      TEE_ATTR_ECC_PUBLIC_VALUE_X,
						      TEE_ATTR_ECC_PUBLIC_VALUE_Y };

	mbedtls_ecdsa_context      *ecc = NULL;
	mbedtls_mpi              attrs[KM_ATTR_COUNT_EC - 1] = {{0}};
	mbedtls_entropy_context  entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ecp_group_id grp_id;
	const mbedtls_pk_info_t *pk_info = NULL;
	int                      mbedtls_ret = 1;
	uint32_t grp_id_sz;

	DMSG("%s %d", __func__, __LINE__);

	mbedtls_pk_init(pk);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);

	TEE_GetObjectInfo1(key_obj, &obj_info);
	mbedtls_ret = mbedtls_ctr_drbg_seed(&ctr_drbg, f_rng,
					    &entropy, NULL, 0);
	if (mbedtls_ret != 0) {
		EMSG("mbedtls_ctr_drbg_seed returned %d\n",
		     mbedtls_ret);
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
	if ((mbedtls_ret = mbedtls_pk_setup(pk, pk_info)) != 0) {
		EMSG("mbedtls_pk_setup returned %d\n",
		     mbedtls_ret);
		res = TEE_ERROR_GENERIC;
		mbedtls_pk_free(pk);
		goto out;
	}

	ecc = (mbedtls_ecdsa_context *)TEE_Malloc(sizeof(mbedtls_ecdsa_context),
						  TEE_MALLOC_FILL_ZERO);

	mbedtls_ecdsa_init(ecc);

	/* check if we work with persistent object, as transient API differs */
	if (obj_info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) {
		/* Read root RSA key attributes */
		res = TEE_SeekObjectData(key_obj, 0, TEE_DATA_SEEK_SET);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to seek root ECC key, res=%x", res);
			res = TEE_ERROR_BAD_STATE;
			goto out;
		}

		/* Read Curve ID TEE_ATTR_ECC_CURVE */
		res = TEE_ReadObjectData(key_obj, &grp_id,
					 sizeof(uint32_t), &read_size);
		if (res != TEE_SUCCESS || read_size != sizeof(uint32_t)) {
			EMSG("Failed to read EC Curve id, res=%x", res);
			return res;
		}

		/*
		 * Reading following attributes:
		 * TEE_ATTR_ECC_PRIVATE_VALUE
		 * TEE_ATTR_ECC_PUBLIC_VALUE_X
		 * TEE_ATTR_ECC_PUBLIC_VALUE_Y
		 */

		for (uint32_t i = 0; i < (KM_ATTR_COUNT_EC - 1); i++) {
			res = TEE_ReadObjectData(key_obj, &key_attr_buf_size,
					sizeof(uint32_t), &read_size);
			if (res) {
				EMSG("Failed to read EC attribute size, res=%x", res);
				return res;
			}
			if (key_attr_buf_size > EC_MAX_KEY_BUFFER_SIZE) {
				EMSG("Invalid EC attribute size %d",
				     key_attr_buf_size);
				res = TEE_ERROR_BAD_STATE;
				return res;
			}
			res = TEE_ReadObjectData(key_obj, key_attr_buf,
						 key_attr_buf_size, &read_size);
			if (res != TEE_SUCCESS || read_size != key_attr_buf_size) {
				EMSG("Failed to read EC attribute buffer, res=%x", res);
				return res;
			}

			/* provide sane value */
			mbedtls_mpi_init(&attrs[i]);

			/* convert to mbedtls mpi structure from binary data */
			if ((mbedtls_ret = mbedtls_mpi_read_binary(&attrs[i],
								  key_attr_buf,
								  key_attr_buf_size)) != 0) {
				EMSG("mbedtls_mpi_read_binary returned %d\n\n",
				     mbedtls_ret);
				res = TEE_ERROR_BAD_FORMAT;

				goto out;
			}
			DHEXDUMP(key_attr_buf, key_attr_buf_size);

		}
	} else {
		/* User transient object API */

		res = TEE_GetObjectValueAttribute(key_obj, TEE_ATTR_ECC_CURVE,
						  &grp_id, &grp_id_sz);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to get curve attribute, res=%x", res);
			goto out;
		}

		for (uint32_t i = 0; i < (KM_ATTR_COUNT_EC - 1); i++) {
			res = TEE_GetObjectBufferAttribute(key_obj,
							   attr_ids[i],
							   key_attr_buf,
							   &key_attr_buf_size);
			if (res != TEE_SUCCESS) {
				EMSG("Failed to get attribute %d, res=%x", i, res);
				goto out;
			}

			/* provide sane value */
			mbedtls_mpi_init(&attrs[i]);

			/* convert to mbedtls mpi structure from binary data */
			if ((mbedtls_ret = mbedtls_mpi_read_binary(&attrs[i],
								  key_attr_buf,
								  key_attr_buf_size)) != 0) {
				EMSG("mbedtls_mpi_read_binary returned %d\n\n",
				     mbedtls_ret);
				res = TEE_ERROR_BAD_FORMAT;

				goto out;
			}
		}
	}

	/*
	 * Filling mbedtls_ecp_group field, mbedTLS IDs correspond
	 * to the same defined optee-os core:
	 *
	 *
	 * #define TEE_ECC_CURVE_NIST_P192             0x00000001
	 * #define TEE_ECC_CURVE_NIST_P224             0x00000002
	 * #define TEE_ECC_CURVE_NIST_P256             0x00000003
	 * #define TEE_ECC_CURVE_NIST_P384             0x00000004
	 * #define TEE_ECC_CURVE_NIST_P521             0x00000005
	 *
	 * enum mbedtls_ecp_group_id {
	 *   MBEDTLS_ECP_DP_NONE = 0,
	 *   MBEDTLS_ECP_DP_SECP192R1,
	 *   MBEDTLS_ECP_DP_SECP224R1,
	 *   MBEDTLS_ECP_DP_SECP256R1,
	 *   MBEDTLS_ECP_DP_SECP384R1,
	 *   MBEDTLS_ECP_DP_SECP521R1,
	 *              ...
	 * }
	 *
	 */
	mbedtls_ret = mbedtls_ecp_group_load(&ecc->grp, grp_id);
	if (mbedtls_ret) {
		EMSG("mbedtls_ecp_group_load: failed: -%#x",
				-mbedtls_ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	if ((mbedtls_ret = mbedtls_mpi_copy(&ecc->Q.X, &attrs[0]) != 0) ||
	    (mbedtls_ret = mbedtls_mpi_copy(&ecc->Q.Y, &attrs[1]) != 0) ||
	    (mbedtls_ret = mbedtls_mpi_copy(&ecc->d, &attrs[2]) != 0) ||
	    (mbedtls_ret = mbedtls_mpi_lset(&ecc->Q.Z, 1 ) != 0)) {
		EMSG("mbedtls_ecc import failed returned %d\n\n", mbedtls_ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	pk->pk_ctx = ecc;

out:
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	for (uint32_t i = 0; i < KM_ATTR_COUNT_EC - 1; i++)
		mbedtls_mpi_free(&attrs[i]);

	if (res != TEE_SUCCESS) {
		mbedtls_ecp_keypair_free(ecc);
		TEE_Free(ecc);
	}

	return res;
}
/* create mbedtls_pk_context based on RSA key attributes */
static TEE_Result mbedTLS_import_rsa_pk(mbedtls_pk_context *pk,
					const TEE_ObjectHandle key_obj)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t   read_size = 0;
	uint8_t    key_attr_buf[RSA_MAX_KEY_BUFFER_SIZE];
	uint32_t   key_attr_buf_size = RSA_MAX_KEY_BUFFER_SIZE;
	TEE_ObjectInfo obj_info;
	const uint32_t attr_ids[KM_ATTR_COUNT_RSA] = { TEE_ATTR_RSA_MODULUS,
						       TEE_ATTR_RSA_PUBLIC_EXPONENT,
						       TEE_ATTR_RSA_PRIVATE_EXPONENT,
						       TEE_ATTR_RSA_PRIME1,
						       TEE_ATTR_RSA_PRIME2,
						       TEE_ATTR_RSA_EXPONENT1,
						       TEE_ATTR_RSA_EXPONENT2,
						       TEE_ATTR_RSA_COEFFICIENT };

	/* mbedTLS-related definitions */
	mbedtls_rsa_context *rsa = NULL;
	mbedtls_mpi attrs[KM_ATTR_COUNT_RSA] = {{0}};
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_mpi K;
	const mbedtls_pk_info_t *pk_info = NULL;
	int mbedtls_ret = 1;

	DMSG("%s %d", __func__, __LINE__);

	mbedtls_pk_init(pk);
	mbedtls_mpi_init(&K);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);

	TEE_GetObjectInfo1(key_obj, &obj_info);

	mbedtls_ret = mbedtls_ctr_drbg_seed(&ctr_drbg, f_rng,
					    &entropy, NULL, 0);
	if (mbedtls_ret != 0) {
		EMSG("mbedtls_ctr_drbg_seed returned %d\n",
		     mbedtls_ret);
		res = TEE_ERROR_GENERIC;
		goto out;
	}

	pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
	if ((mbedtls_ret = mbedtls_pk_setup(pk, pk_info)) != 0) {
		EMSG("mbedtls_pk_setup returned %d\n",
		     mbedtls_ret);
		res = TEE_ERROR_GENERIC;
		mbedtls_pk_free(pk);
		goto out;
	}

	rsa = (mbedtls_rsa_context *) TEE_Malloc(sizeof(mbedtls_rsa_context),
					       TEE_MALLOC_FILL_ZERO);
	if (rsa == NULL)
	{
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	mbedtls_rsa_init(rsa, MBEDTLS_RSA_PKCS_V15, 0);

	/* check if we work with persistent object, as transient API differs */
	if (obj_info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT) {
		/* Read root RSA key attributes */
		res = TEE_SeekObjectData(key_obj, 0, TEE_DATA_SEEK_SET);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to seek root RSA key, res=%x", res);
			res = TEE_ERROR_BAD_STATE;
			goto out;
		}

		/*
		 * Attribute order in attrs array:
		 * n
		 * e
		 * d
		 * p
		 * q
		 * dp
		 * dq
		 * qp
		 */
		for (uint32_t i = 0; i < KM_ATTR_COUNT_RSA; i++) {
			res = TEE_ReadObjectData(key_obj, &key_attr_buf_size,
						 sizeof(uint32_t), &read_size);
			if (res) {
				EMSG("Failed to read RSA attribute size, res=%x", res);
				res = TEE_ERROR_BAD_STATE;
				goto out;
			}

			if (key_attr_buf_size > RSA_MAX_KEY_BUFFER_SIZE) {
				EMSG("Invalid RSA attribute size %d",
				     key_attr_buf_size);
				res = TEE_ERROR_BAD_STATE;
				goto out;
			}

			res = TEE_ReadObjectData(key_obj, key_attr_buf,
						 key_attr_buf_size, &read_size);
			if (res != TEE_SUCCESS || read_size != key_attr_buf_size) {
				EMSG("Failed to read RSA attribute buffer, res=%x",
				     res);
				goto out;
			}

			/* provide sane value */
			mbedtls_mpi_init(&attrs[i]);

			/* convert to mbedtls mpi structure from binary data */
			if ((mbedtls_ret = mbedtls_mpi_read_binary(&attrs[i],
								  key_attr_buf,
								  key_attr_buf_size)) != 0) {
				EMSG("mbedtls_mpi_read_binary returned %d\n\n",
				     mbedtls_ret);
				res = TEE_ERROR_BAD_FORMAT;

				goto out;
			}
		}
	} else {
		/* User transient object API */

		for (uint32_t i = 0; i < KM_ATTR_COUNT_RSA; i++) {
			res = TEE_GetObjectBufferAttribute(key_obj,
							   attr_ids[i],
							   key_attr_buf,
							   &key_attr_buf_size);

			/* provide sane value */
			mbedtls_mpi_init(&attrs[i]);

			/* convert to mbedtls mpi structure from binary data */
			if ((mbedtls_ret = mbedtls_mpi_read_binary(&attrs[i],
								  key_attr_buf,
								  key_attr_buf_size)) != 0) {
				EMSG("mbedtls_mpi_read_binary returned %d\n\n",
				     mbedtls_ret);
				res = TEE_ERROR_BAD_FORMAT;

				goto out;
			}
		}
	}

	/* N, P, Q, D, E */
	if ((mbedtls_ret = mbedtls_mpi_copy(&rsa->N, &attrs[0]) != 0) ||
	    (mbedtls_ret = mbedtls_mpi_copy(&rsa->P, &attrs[3]) != 0) ||
	    (mbedtls_ret = mbedtls_mpi_copy(&rsa->Q, &attrs[4]) != 0) ||
	    (mbedtls_ret = mbedtls_mpi_copy(&rsa->D, &attrs[2]) != 0) ||
	    (mbedtls_ret = mbedtls_mpi_copy(&rsa->E, &attrs[1]) != 0)) {
		EMSG("mbedtls_rsa import failed returned %d\n\n", mbedtls_ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	rsa->len = mbedtls_mpi_size(&rsa->N);

	/* Deduce CRT */
	mbedtls_mpi_sub_int(&K, &rsa->P, 1);
	mbedtls_mpi_mod_mpi(&rsa->DP, &rsa->D, &K);
	mbedtls_mpi_sub_int(&K, &rsa->Q, 1);
	mbedtls_mpi_mod_mpi(&rsa->DQ, &rsa->D, &K);
	mbedtls_mpi_inv_mod(&rsa->QP, &rsa->Q, &rsa->P);

	pk->pk_ctx = rsa;

out:
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_mpi_free(&K);

	for (uint32_t i = 0; i < KM_ATTR_COUNT_RSA; i++)
		mbedtls_mpi_free(&attrs[i]);

	if (res != TEE_SUCCESS) {
		mbedtls_rsa_free(rsa);
		TEE_Free(rsa);
	}

	return res;
}

static TEE_Result mbedTLS_gen_root_cert(mbedtls_pk_context *issuer_key,
					keymaster_blob_t *root_cert,
					const char *cert_subject)
{
	unsigned char buf[CERT_ROOT_MAX_SIZE];
	int blen = CERT_ROOT_MAX_SIZE;
	int ret;
	TEE_Result res = TEE_SUCCESS;

	mbedtls_mpi serial;
	mbedtls_x509write_cert crt;

	DMSG("%s %d", __func__, __LINE__);
	mbedtls_mpi_init(&serial);
	mbedtls_x509write_crt_init(&crt);

	ret = mbedtls_mpi_lset(&serial, 1);
	if (ret) {
		EMSG("mbedtls_mpi_read_string: failed: -%#x", -ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	ret = mbedtls_x509write_crt_set_subject_name(&crt, cert_subject);
	if (ret) {
		EMSG("mbedtls_x509write_crt_set_subject_name: failed: -%#x",
				-ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	ret = mbedtls_x509write_crt_set_issuer_name(&crt, cert_subject);
	if (ret) {
		EMSG("mbedtls_x509write_crt_set_issuer_name: failed: -%#x",
				-ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	mbedtls_x509write_crt_set_version( &crt, MBEDTLS_X509_CRT_VERSION_3 );
	mbedtls_x509write_crt_set_md_alg(&crt,  MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_subject_key(&crt, issuer_key);
	mbedtls_x509write_crt_set_issuer_key(&crt, issuer_key);

	ret = mbedtls_x509write_crt_set_serial(&crt, &serial);
	if (ret) {
		EMSG("mbedtls_x509write_crt_set_serial: failed: -%#x", -ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	ret = mbedtls_x509write_crt_set_validity(&crt, "19700101000000",
						 "20301231235959");
	if (ret) {
		EMSG("mbedtls_x509write_crt_set_validity: failed: -%#x", -ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	ret = mbedtls_x509write_crt_set_basic_constraints(&crt, 1, -1);
	if (ret) {
		EMSG("mbedtls_x509write_crt_set_validity: failed: -%#x", -ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	ret = mbedtls_x509write_crt_set_subject_key_identifier(&crt);
	if (ret) {
		EMSG("mbedtls_x509write_crt_set_subject_key_identifier: failed: -%#x",
				-ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	ret = mbedtls_x509write_crt_set_authority_key_identifier(&crt);
	if (ret) {
		EMSG("mbedtls_x509write_crt_set_authority_key_identifier: failed: -%#x",
				-ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	ret = mbedtls_x509write_crt_set_key_usage(&crt,
					    MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
					    MBEDTLS_X509_KU_KEY_CERT_SIGN);
	if (ret) {
		EMSG("mbedtls_x509write_crt_set_key_usage: failed: -%#x",
				-ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	/*
	 * from https://tls.mbed.org/api/x509__crt_8h.html:
	 * Write a built up certificate to a X509 DER structure Note: data is
	 * written at the end of the buffer! Use the return value to determine
	 * where you should start using the buffer.
	 */
	ret = mbedtls_x509write_crt_der(&crt, buf, blen, f_rng, NULL);
	if (ret < 0) {
		EMSG("mbedtls_x509write_crt_der: failed: -%#x",
				-ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	if (root_cert->data_length < (uint32_t)ret)
	{
		res = TEE_ERROR_SHORT_BUFFER;
		root_cert->data_length = ret;
		goto out;
	}
	root_cert->data_length = ret;
	TEE_MemMove(root_cert->data, buf + blen - ret,
			ret);

out:
	mbedtls_mpi_free(&serial);
	mbedtls_x509write_crt_free(&crt);

	return res;
}


TEE_Result mbedTLS_gen_root_cert_rsa(TEE_ObjectHandle rsa_root_key,
				     keymaster_blob_t *rsa_root_cert)
{
	TEE_Result res = TEE_SUCCESS;
	mbedtls_pk_context issuer_key;

	DMSG("%s %d", __func__, __LINE__);
	res = mbedTLS_import_rsa_pk(&issuer_key, rsa_root_key);
	if (res) {
		EMSG("mbedTLS_import_rsa_pk: failed: %#x", res);
		return res;
	}

	res = mbedTLS_gen_root_cert(&issuer_key, rsa_root_cert, cert_root_subject_rsa);
	if (res != TEE_ERROR_SHORT_BUFFER)
	{
		EMSG("mbedTLS_gen_root_cert: failed: %#x", res);
		goto out;
	}
	rsa_root_cert->data = TEE_Malloc(rsa_root_cert->data_length, TEE_MALLOC_FILL_ZERO);
	if (rsa_root_cert->data == NULL)
	{
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	res = mbedTLS_gen_root_cert(&issuer_key, rsa_root_cert, cert_root_subject_rsa);
	if (res != TEE_SUCCESS ) {
		EMSG("mbedTLS_gen_root_cert: failed: %#x", res);
		goto out;
	}
out:
	mbedtls_pk_free(&issuer_key);

	return res;
}


TEE_Result mbedTLS_gen_root_cert_ecc(TEE_ObjectHandle ecc_root_key,
				     keymaster_blob_t *ecc_root_cert)
{
	TEE_Result res = TEE_SUCCESS;
	mbedtls_pk_context issuer_key;

	DMSG("%s %d", __func__, __LINE__);
	res = mbedTLS_import_ecc_pk(&issuer_key, ecc_root_key);
	if (res) {
		EMSG("mbedTLS_import_ecc_pk: failed: %#x", res);
		return res;
	}

	res = mbedTLS_gen_root_cert(&issuer_key, ecc_root_cert, cert_root_subject_ecc);
	if (res != TEE_ERROR_SHORT_BUFFER)
	{
		EMSG("mbedTLS_gen_root_cert: failed: %#x", res);
		goto out;
	}
	ecc_root_cert->data = TEE_Malloc(ecc_root_cert->data_length, TEE_MALLOC_FILL_ZERO);
	if (ecc_root_cert->data == NULL)
	{
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	res = mbedTLS_gen_root_cert(&issuer_key, ecc_root_cert, cert_root_subject_ecc);
	if (res != TEE_SUCCESS ) {
		EMSG("mbedTLS_gen_root_cert: failed: %#x", res);
		goto out;
	}
out:
	mbedtls_pk_free(&issuer_key);

	return res;
}

static TEE_Result mbedTLS_attest_key_cert(mbedtls_pk_context *issuer_key,
					  mbedtls_pk_context *subject_key,
					  keymaster_blob_t *attest_cert,
					  keymaster_blob_t *attest_ext,
					  char *cert_issuer)
{
	unsigned char buf[CERT_ROOT_MAX_SIZE];
	int blen = CERT_ROOT_MAX_SIZE;
	int ret;
	TEE_Result res = TEE_SUCCESS;

	mbedtls_mpi serial;
	mbedtls_x509write_cert crt;
	const char *attestation_oid = MBEDTLS_OID_ATTESTATION;

	DMSG("%s %d", __func__, __LINE__);

	mbedtls_mpi_init(&serial);
	mbedtls_x509write_crt_init(&crt);

	ret = mbedtls_mpi_lset(&serial, 1);
	if (ret) {
		EMSG("mbedtls_mpi_read_string: failed: -%#x", -ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	ret = mbedtls_x509write_crt_set_subject_name(&crt,
						     cert_attest_key_subject);
	if (ret) {
		EMSG("mbedtls_x509write_crt_set_subject_name: failed: -%#x",
				-ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	ret = mbedtls_x509write_crt_set_issuer_name(&crt, cert_issuer);
	if (ret) {
		EMSG("mbedtls_x509write_crt_set_issuer_name: failed: -%#x",
				-ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	mbedtls_x509write_crt_set_version( &crt, MBEDTLS_X509_CRT_VERSION_3 );
	mbedtls_x509write_crt_set_md_alg(&crt,  MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_subject_key(&crt, subject_key);
	mbedtls_x509write_crt_set_issuer_key(&crt, issuer_key);

	ret = mbedtls_x509write_crt_set_serial(&crt, &serial);
	if (ret) {
		EMSG("mbedtls_x509write_crt_set_serial: failed: -%#x", -ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	ret = mbedtls_x509write_crt_set_validity(&crt, "19700101000000",
						 "20301231235959");
	if (ret) {
		EMSG("mbedtls_x509write_crt_set_validity: failed: -%#x", -ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	ret = mbedtls_x509write_crt_set_basic_constraints(&crt, 1, -1);
	if (ret) {
		EMSG("mbedtls_x509write_crt_set_basic_constraints: failed: -%#x", -ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	ret = mbedtls_x509write_crt_set_subject_key_identifier(&crt);
	if (ret) {
		EMSG("mbedtls_x509write_crt_set_subject_key_identifier: failed: -%#x",
				-ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	ret = mbedtls_x509write_crt_set_authority_key_identifier(&crt);
	if (ret) {
		EMSG("mbedtls_x509write_crt_set_authority_key_identifier: failed: -%#x",
				-ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	ret = mbedtls_x509write_crt_set_key_usage(&crt,
					    MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
					    MBEDTLS_X509_KU_KEY_CERT_SIGN);
	if (ret) {
		EMSG("mbedtls_x509write_crt_set_key_usage: failed: -%#x",
				-ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	/* add attestation OID */
	ret =  mbedtls_x509write_crt_set_extension(&crt, attestation_oid,
						   MBEDTLS_OID_SIZE(MBEDTLS_OID_ATTESTATION),
			                           1, attest_ext->data, attest_ext->data_length);
	if (ret) {
		EMSG("mbedtls_x509write_crt_set_key_usage: failed: -%#x",
				-ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}
	/*
	 * from https://tls.mbed.org/api/x509__crt_8h.html:
	 * Write a built up certificate to a X509 DER structure Note: data is
	 * written at the end of the buffer! Use the return value to determine
	 * where you should start using the buffer.
	 */
	ret = mbedtls_x509write_crt_der(&crt, buf, blen, f_rng, NULL);
	if (ret < 0) {
		EMSG("mbedtls_x509write_crt_der: failed: -%#x",
				-ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	if (attest_cert->data_length < (uint32_t)ret)
	{
		res = TEE_ERROR_SHORT_BUFFER;
		attest_cert->data_length = ret;
		goto out;
	}
	attest_cert->data_length = ret;

	TEE_MemMove(attest_cert->data, buf + blen - ret,
			ret);

out:
	mbedtls_mpi_free(&serial);
	mbedtls_x509write_crt_free(&crt);

	return res;
}

TEE_Result mbedTLS_gen_attest_key_cert_rsa(TEE_ObjectHandle rsa_root_key,
						TEE_ObjectHandle rsa_attest_key,
						keymaster_cert_chain_t *cert_chain,
						keymaster_blob_t *attest_ext)
{
	int ret;
	TEE_Result res = TEE_SUCCESS;
	keymaster_blob_t *rsa_attest_cert = &cert_chain->entries[KEY_ATT_CERT_INDEX];
	mbedtls_pk_context issuer_key = {0};
	mbedtls_pk_context subject_key = {0};
	mbedtls_x509_crt *cert = NULL;
   	char cert_subject_rsa[1024];
    const unsigned char *p = (unsigned char*)cert_chain->entries[ROOT_ATT_CERT_INDEX].data;
    size_t cert_len = cert_chain->entries[ROOT_ATT_CERT_INDEX].data_length;

	DMSG("%s %d", __func__, __LINE__);

    cert = (mbedtls_x509_crt*)TEE_Malloc( sizeof( mbedtls_x509_crt ), TEE_MALLOC_FILL_ZERO );
    if( cert == NULL )
        return TEE_ERROR_OUT_OF_MEMORY;

    mbedtls_x509_crt_init( cert );

    if( ( mbedtls_x509_crt_parse_der( cert,
                                            p, cert_len ) ) != 0 )
    {
		EMSG("mbedtls_x509_crt_parse_der: failed");
        res = TEE_ERROR_BAD_PARAMETERS;
    	goto out;
    }

	res = mbedTLS_import_rsa_pk(&issuer_key, rsa_root_key);
	if (res) {
		EMSG("mbedTLS_import_rsa_pk: failed: %#x", res);
		goto out;
	}

	res = mbedTLS_import_rsa_pk(&subject_key, rsa_attest_key);
	if (res) {
		EMSG("mbedTLS_import_rsa_pk: failed: %#x", res);
		goto out;
	}

	ret = mbedtls_x509_dn_gets( cert_subject_rsa, sizeof(cert_subject_rsa)-1, &cert->subject );
	if ( ret < 0) {
		EMSG("mbedtls_x509_dn_gets: failed: -%#x", -ret);
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	res = mbedTLS_attest_key_cert(&issuer_key, &subject_key,
				rsa_attest_cert, attest_ext, cert_subject_rsa );
	if (res) {
		EMSG("mbedTLS_attest_key_cert: failed: %#x", res);
		goto out;
	}
out:
	mbedtls_pk_free(&issuer_key);
	mbedtls_pk_free(&subject_key);
    mbedtls_x509_crt_free( cert );
    TEE_Free( cert );

	return res;
}

TEE_Result mbedTLS_gen_attest_key_cert_ecc(TEE_ObjectHandle ecc_root_key,
					   	TEE_ObjectHandle ecc_attest_key,
						keymaster_cert_chain_t *cert_chain,
						keymaster_blob_t *attest_ext)
{
	int ret;
	TEE_Result res = TEE_SUCCESS;
	keymaster_blob_t *ecc_attest_cert = &cert_chain->entries[KEY_ATT_CERT_INDEX];
	mbedtls_pk_context issuer_key = {0};
	mbedtls_pk_context subject_key = {0};
	mbedtls_x509_crt *cert = NULL;
   	char cert_subject_ecc[1024];
    const unsigned char *p = (unsigned char*)cert_chain->entries[ROOT_ATT_CERT_INDEX].data;
    size_t cert_len = cert_chain->entries[ROOT_ATT_CERT_INDEX].data_length;

	DMSG("%s %d", __func__, __LINE__);

    cert = (mbedtls_x509_crt*)TEE_Malloc( sizeof( mbedtls_x509_crt ), TEE_MALLOC_FILL_ZERO );
    if( cert == NULL )
        return TEE_ERROR_OUT_OF_MEMORY;

    mbedtls_x509_crt_init( cert );

    if( ( mbedtls_x509_crt_parse_der( cert,
                                            p, cert_len ) ) != 0 )
    {
		EMSG("mbedtls_x509_crt_parse_der: failed");
        res = TEE_ERROR_BAD_PARAMETERS;
    	goto out;
    }

	res = mbedTLS_import_ecc_pk(&issuer_key, ecc_root_key);
	if (res) {
		EMSG("mbedTLS_import_ecc_pk issuer_key: failed: %#x", res);
		return res;
	}

	res = mbedTLS_import_ecc_pk(&subject_key, ecc_attest_key);
	if (res) {
		EMSG("mbedTLS_import_ecc_pk subject_key: failed: %#x", res);
		return res;
	}

	ret = mbedtls_x509_dn_gets( cert_subject_ecc, sizeof(cert_subject_ecc)-1, &cert->subject );
	if ( ret < 0) {
		EMSG("mbedtls_x509_dn_gets: failed: -%#x", -ret);
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	res = mbedTLS_attest_key_cert(&issuer_key, &subject_key,
				ecc_attest_cert, attest_ext, cert_subject_ecc );
	if (res) {
		EMSG("mbedTLS_attest_key_cert: failed: %#x", res);
		goto out;
	}
out:
	mbedtls_pk_free(&issuer_key);
	mbedtls_pk_free(&subject_key);
    mbedtls_x509_crt_free( cert );
    TEE_Free( cert );

	return res;
}
