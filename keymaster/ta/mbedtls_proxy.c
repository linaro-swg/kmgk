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
const char *cert_subject_rsa = "OU=" CERT_ROOT_ORG_UNIT_RSA
			       ",O=" CERT_ROOT_ORG
			       ",CN=" CERT_ROOT_ORG;

const char *cert_subject_ecc = "OU=" CERT_ROOT_ORG_UNIT_ECC
			       ",O=" CERT_ROOT_ORG
			       ",CN=" CERT_ROOT_ORG;

const uint32_t cert_version = 2;	/* x509 version of cert. v3 used. */
const uint32_t cert_version_tag;	/* tag value for version field. */
const uint32_t cert_serial_number = 1;	/* serialNumber of cert. */

/* entropy source */
static int f_rng(void *rng __unused, unsigned char *output, size_t output_len)
{
	TEE_GenerateRandom(output, output_len);
	return 0;
}

/* create mbedtls_pk_context based on RSA key attributes */
static TEE_Result mbedTLS_import_rsa_pk(mbedtls_pk_context *pk,
					const TEE_ObjectHandle key_obj)
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t   read_size = 0;
	uint8_t    key_attr_buf[RSA_KEY_BUFFER_SIZE];
	uint32_t   key_attr_buf_size = RSA_KEY_BUFFER_SIZE;

	/* mbedTLS-related definitions */
	mbedtls_rsa_context      *rsa;
	mbedtls_mpi              attrs[KM_ATTR_COUNT_RSA];
	mbedtls_entropy_context  entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_mpi K;
	const mbedtls_pk_info_t *pk_info;
	int                      mbedtls_ret = 1;

	DMSG("%s %d", __func__, __LINE__);

	mbedtls_pk_init(pk);
	mbedtls_mpi_init(&K);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);

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

	mbedtls_rsa_init(rsa, MBEDTLS_RSA_PKCS_V15, 0);

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
		if (res != TEE_SUCCESS || read_size != sizeof(uint32_t)) {
			EMSG("Failed to read RSA attribute size, res=%x", res);
			res = TEE_ERROR_BAD_STATE;
			goto out;
		}

		if (key_attr_buf_size > RSA_KEY_BUFFER_SIZE) {
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

	if (res != TEE_SUCCESS)
		TEE_Free(rsa);
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

	DMSG("Generated certificate: \n");
	DHEXDUMP(buf + blen - ret, ret);

	root_cert->data_length = ret;
	root_cert->data = TEE_Malloc(root_cert->data_length,
				     TEE_MALLOC_FILL_ZERO);
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

	mbedTLS_gen_root_cert(&issuer_key, rsa_root_cert, cert_subject_rsa);
	if (res) {
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
}
