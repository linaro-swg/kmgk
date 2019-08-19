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
#include <mbedtls/ecdsa.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/x509.h>
#include <mbedtls/pk.h>
#include <mbedtls/asn1write.h>


#define CERT_ROOT_ORG "Android"
#define CERT_ROOT_ORG_UNIT_RSA "Attestation RSA root CA"
#define CERT_ROOT_ORG_UNIT_ECC "Attestation ECC root CA"
#define CERT_ROOT_MAX_SIZE 4096

#define MBEDTLS_OID_ATTESTATION "\x2B\x06\x01\x04\x01\xD6\x79\x02\x01\x11"

/*
 * RSA public keys:
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {          1 + 3
 *       algorithm            AlgorithmIdentifier,  1 + 1 (sequence)
 *                                                + 1 + 1 + 9 (rsa oid)
 *                                                + 1 + 1 (params null)
 *       subjectPublicKey     BIT STRING }          1 + 3 + (1 + below)
 *  RSAPublicKey ::= SEQUENCE {                     1 + 3
 *      modulus           INTEGER,  -- n            1 + 3 + MPI_MAX + 1
 *      publicExponent    INTEGER   -- e            1 + 3 + MPI_MAX + 1
 *  }
 */
#define RSA_MAX_BYTES   38 + 2 * MBEDTLS_MPI_MAX_SIZE

/*
 * EC public keys:
 *  SubjectPublicKeyInfo  ::=  SEQUENCE  {      1 + 2
 *    algorithm         AlgorithmIdentifier,    1 + 1 (sequence)
 *                                            + 1 + 1 + 7 (ec oid)
 *                                            + 1 + 1 + 9 (namedCurve oid)
 *    subjectPublicKey  BIT STRING              1 + 2 + 1               [1]
 *                                            + 1 (point format)        [1]
 *                                            + 2 * ECP_MAX (coords)    [1]
 *  }
 */
#define EC_MAX_BYTES   30 + 2 * MBEDTLS_ECP_MAX_BYTES

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

static int mpi_to_att(TEE_Attribute *att, const mbedtls_mpi *mpi,
		      uint32_t tag) {
	uint32_t length = (uint32_t)mbedtls_mpi_size(mpi);
	uint8_t *buf = TEE_Malloc(length, TEE_MALLOC_FILL_ZERO);
	if (!buf) {
		EMSG("Failed to allocate memory");
		return -1;
	}

	if (mbedtls_mpi_write_binary(mpi, buf, length)) {
		EMSG ("Failed to write mpi to buffer");
		TEE_Free(buf);
		return -1;
	}

	TEE_InitRefAttribute(att, tag, buf, length);

	return 0;
}
/* Structure for conversion from mbedtls_mpi to TEE_Attribute */
struct mpi_id {
	uint32_t att_id;
	mbedtls_mpi *mpi;
};

/* Convert mbedtls_rsa_context* to TEE_Attributes array */
static keymaster_error_t mbedtls_export_rsa(TEE_Attribute **attrs,
					    uint32_t *attrs_count,
					    uint32_t *key_size,
					    mbedtls_pk_context *context) {
	mbedtls_rsa_context *ctx = context->pk_ctx;
	uint32_t max_attrs = KM_ATTR_COUNT_RSA, count = 0;
	keymaster_error_t ret = KM_ERROR_UNKNOWN_ERROR;
	struct mpi_id mpis[KM_ATTR_COUNT_RSA] = {
		{ TEE_ATTR_RSA_MODULUS, &ctx->N },
		{ TEE_ATTR_RSA_PUBLIC_EXPONENT, &ctx->E},
		{ TEE_ATTR_RSA_PRIVATE_EXPONENT, &ctx->D},
		{ TEE_ATTR_RSA_PRIME1, &ctx->P },
		{ TEE_ATTR_RSA_PRIME2, &ctx->Q },
		{ TEE_ATTR_RSA_EXPONENT1, &ctx->DP },
		{ TEE_ATTR_RSA_EXPONENT2, &ctx->DQ },
		{ TEE_ATTR_RSA_COEFFICIENT, &ctx->QP },
	};

	TEE_Attribute *att = TEE_Malloc(sizeof(TEE_Attribute) * max_attrs,
					TEE_MALLOC_FILL_ZERO);

	if (!att) {
		EMSG("Failed to allocate memory");
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	for (uint32_t i = 0; i < KM_ATTR_COUNT_RSA; i++) {
		if (mpi_to_att(&att[i], mpis[i].mpi, mpis[i].att_id)) {
			EMSG("Failed to write mpi to att");
			goto out;
		}

		count++;
	}

	*attrs = att;
	*attrs_count = KM_ATTR_COUNT_RSA;
	*key_size = (uint32_t)mbedtls_pk_get_bitlen(context);
	ret = KM_ERROR_OK;

out:
	if (ret != KM_ERROR_OK)
		free_attrs(att, count);

	return ret;
}

/* Convert mbedtls_ecdsa_context* to TEE_Attributes array */
static keymaster_error_t mbedtls_export_ecdsa(TEE_Attribute **attrs,
					      uint32_t *attrs_count,
					      uint32_t *key_size,
					      mbedtls_pk_context *context) {
	mbedtls_ecdsa_context *ctx = context->pk_ctx;
	uint32_t max_attrs = KM_ATTR_COUNT_EC, count = 0;
	uint32_t curve;
	keymaster_error_t ret = KM_ERROR_UNKNOWN_ERROR;
	struct mpi_id mpis[KM_ATTR_COUNT_EC - 1] = {
		{ TEE_ATTR_ECC_PRIVATE_VALUE, &ctx->d },
		{ TEE_ATTR_ECC_PUBLIC_VALUE_X, &ctx->Q.X },
		{ TEE_ATTR_ECC_PUBLIC_VALUE_Y, &ctx->Q.Y }
	};

	TEE_Attribute *att = TEE_Malloc(sizeof(TEE_Attribute) * max_attrs,
					TEE_MALLOC_FILL_ZERO);

	if (!att) {
		EMSG("Failed to allocate memory");
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	for (uint32_t i = 0; i < KM_ATTR_COUNT_EC - 1; i++) {
		if (mpi_to_att(&att[i], mpis[i].mpi, mpis[i].att_id)) {
			EMSG("Failed to write mpi to att");
			goto out;
		}

		count++;
	}

	*key_size = (uint32_t)mbedtls_pk_get_bitlen(context);
	curve = TA_get_curve_nist(*key_size);

	EMSG ("key_size = %u", *key_size);

	TEE_InitValueAttribute(&att[KM_ATTR_COUNT_EC - 1],
			       TEE_ATTR_ECC_CURVE, curve, 0);

	*attrs = att;
	*attrs_count = KM_ATTR_COUNT_EC;

	ret = KM_ERROR_OK;

out:
	if (ret != KM_ERROR_OK)
		free_attrs(att, count);

	return KM_ERROR_OK;
}

keymaster_error_t mbedTLS_decode_pkcs8(keymaster_blob_t key_data,
				       TEE_Attribute **attrs,
				       uint32_t *attrs_count,
				       const keymaster_algorithm_t algorithm,
				       uint32_t *key_size,
				       uint64_t *rsa_public_exponent)
{
	mbedtls_pk_context pk;
	keymaster_error_t ret = KM_ERROR_UNKNOWN_ERROR;
	mbedtls_pk_type_t pk_type;
	uint64_t rsa_exp = 0;

	keymaster_error_t (*pfn_export_ctx)(TEE_Attribute **, uint32_t *,
					    uint32_t *, mbedtls_pk_context *);

	mbedtls_pk_init(&pk);
	int mbedtls_ret = mbedtls_pk_parse_key(&pk, key_data.data,
				       key_data.data_length, NULL, 0);
	if (mbedtls_ret != 0) {
		EMSG("Failed to parse pkcs8 key");
		return KM_ERROR_INVALID_KEY_BLOB;
	}

	pk_type = mbedtls_pk_get_type(&pk);

	if ((algorithm == KM_ALGORITHM_RSA && pk_type != MBEDTLS_PK_RSA) ||
	    (algorithm == KM_ALGORITHM_EC && pk_type != MBEDTLS_PK_ECKEY)) {
		EMSG ("Algorithm mismatch.");
		ret = KM_ERROR_INVALID_KEY_BLOB;
		goto out;
	}

	if (algorithm == KM_ALGORITHM_RSA &&
	    rsa_public_exponent && *rsa_public_exponent == UNDEFINED) {
		mbedtls_rsa_context *ctx = pk.pk_ctx;
		size_t len = mbedtls_mpi_size(&ctx->E);

		if(len > sizeof(rsa_exp)) {
			EMSG("Wrond public exponent");
			goto out;
		}

		mbedtls_mpi_write_binary(&ctx->E,
					 (unsigned char*)&rsa_exp,
					 sizeof(rsa_exp));

		*rsa_public_exponent = TEE_U64_FROM_BIG_ENDIAN(rsa_exp);
	}

	pfn_export_ctx = algorithm == KM_ALGORITHM_RSA ? mbedtls_export_rsa :
							 mbedtls_export_ecdsa;
	ret = pfn_export_ctx(attrs, attrs_count, key_size, &pk);
	if (ret) {
		EMSG("Failed to export context");
		goto out;
	}
out:
	mbedtls_pk_free(&pk);
	return ret;
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

	ecc = pk->pk_ctx;

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
			key_attr_buf_size = EC_MAX_KEY_BUFFER_SIZE;

			res = TEE_GetObjectBufferAttribute(key_obj,
							   attr_ids[i],
							   key_attr_buf,
							   &key_attr_buf_size);
			if (res != TEE_SUCCESS) {
				EMSG("Failed to get attribute %d size %d, res=%x", i, key_attr_buf_size, res);
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

	if ((mbedtls_ret = mbedtls_mpi_copy(&ecc->Q.X, &attrs[1]) != 0) ||
	    (mbedtls_ret = mbedtls_mpi_copy(&ecc->Q.Y, &attrs[2]) != 0) ||
	    (mbedtls_ret = mbedtls_mpi_copy(&ecc->d, &attrs[0]) != 0) ||
	    (mbedtls_ret = mbedtls_mpi_lset(&ecc->Q.Z, 1 ) != 0)) {
		EMSG("mbedtls_ecc import failed returned %d\n\n", mbedtls_ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

out:
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	for (uint32_t i = 0; i < KM_ATTR_COUNT_EC - 1; i++)
		mbedtls_mpi_free(&attrs[i]);

	if (res != TEE_SUCCESS) {
		mbedtls_ecp_keypair_free(ecc);
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

	rsa = pk->pk_ctx;

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

			key_attr_buf_size = RSA_MAX_KEY_BUFFER_SIZE;
			res = TEE_GetObjectBufferAttribute(key_obj,
							   attr_ids[i],
							   key_attr_buf,
							   &key_attr_buf_size);
			if (res != TEE_SUCCESS)
			{
				EMSG("Failed to get attribute %d size %d, res=%x", i, key_attr_buf_size, res);
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

	//https://github.com/linaro-swg/kmgk/pull/3/commits/19f4163e47cbd96d5e98f9c315e88b3d51173ff9#r239748286
	// TODO: blinding to mitigate against Bellcore attack
	/* Deduce CRT */
	mbedtls_mpi_sub_int(&K, &rsa->P, 1);
	mbedtls_mpi_mod_mpi(&rsa->DP, &rsa->D, &K);
	mbedtls_mpi_sub_int(&K, &rsa->Q, 1);
	mbedtls_mpi_mod_mpi(&rsa->DQ, &rsa->D, &K);
	mbedtls_mpi_inv_mod(&rsa->QP, &rsa->Q, &rsa->P);

out:
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_mpi_free(&K);

	for (uint32_t i = 0; i < KM_ATTR_COUNT_RSA; i++)
		mbedtls_mpi_free(&attrs[i]);

	if (res != TEE_SUCCESS) {
		mbedtls_rsa_free(rsa);
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

	// TODO: replace "19700101000000" with current time
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

	if (root_cert->data_length < (uint32_t)ret)
	{
		res = TEE_ERROR_SHORT_BUFFER;
		root_cert->data_length = ret;
		goto out;
	}
	root_cert->data_length = ret;
	TEE_MemMove(root_cert->data, buf + blen - ret,
			ret);
	// TODO: check root_cert->data

out:
	mbedtls_mpi_free(&serial);
	mbedtls_x509write_crt_free(&crt);

	return res;
}

keymaster_error_t mbedTLS_encode_key(keymaster_blob_t *export_data,
                                     const uint32_t type,
                                     const TEE_ObjectHandle *obj_h) {
	mbedtls_pk_context pk;
	uint8_t buf[RSA_MAX_BYTES > EC_MAX_BYTES ? RSA_MAX_BYTES :
						   EC_MAX_BYTES];
	keymaster_error_t ret = KM_ERROR_UNKNOWN_ERROR;
	TEE_Result res;
	int len;

	if (type == TEE_TYPE_ECDSA_KEYPAIR)
		res = mbedTLS_import_ecc_pk(&pk, *obj_h);
	else if (type == TEE_TYPE_RSA_KEYPAIR)
		res = mbedTLS_import_rsa_pk(&pk, *obj_h);

	if (res != TEE_SUCCESS) {
		EMSG("Failed to import PK context");
		return ret;
	}

	len = mbedtls_pk_write_pubkey_der(&pk, buf, sizeof(buf));
	if (len < 0) {
		EMSG("Failed to write PK context to DER");
		goto out;
	}

	export_data->data = TEE_Malloc((uint32_t)len, TEE_MALLOC_FILL_ZERO);
	if (!export_data->data) {
		EMSG("No memory left on device");
		ret = KM_ERROR_MEMORY_ALLOCATION_FAILED;
		goto out;
	}
	export_data->data_length = (size_t)len;
	TEE_MemMove(export_data->data, buf, (uint32_t)len);

out:
	mbedtls_pk_free(&pk);
	return ret;
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
		TEE_Free(rsa_root_cert->data);
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
		TEE_Free(ecc_root_cert->data);
		goto out;
	}
out:
	mbedtls_pk_free(&issuer_key);

	return res;
}

static TEE_Result mbedTLS_attest_key_cert(mbedtls_pk_context *issuer_key,
					  mbedtls_pk_context *subject_key,
					  unsigned int key_usage,
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

	// TODO: replace "19700101000000" with current time
	ret = mbedtls_x509write_crt_set_validity(&crt, "19700101000000",
						 "20301231235959");
	if (ret) {
		EMSG("mbedtls_x509write_crt_set_validity: failed: -%#x", -ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	/* cA to false cause key_usage do not contain MBEDTLS_X509_KU_KEY_CERT_SIGN */
	ret = mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1);
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
					    key_usage);
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
	// TODO: check attest_cert->data

out:
	mbedtls_mpi_free(&serial);
	mbedtls_x509write_crt_free(&crt);

	return res;
}

TEE_Result mbedTLS_gen_attest_key_cert_rsa(TEE_ObjectHandle rsa_root_key,
						TEE_ObjectHandle rsa_attest_key,
						unsigned int key_usage,
						keymaster_cert_chain_t *cert_chain,
						keymaster_blob_t *attest_ext)
{
	int ret;
	TEE_Result res = TEE_SUCCESS;
	keymaster_blob_t *rsa_attest_cert = &cert_chain->entries[KEY_ATT_CERT_INDEX];
	mbedtls_pk_context issuer_key = {NULL,NULL};
	mbedtls_pk_context subject_key = {NULL,NULL};
	mbedtls_x509_crt *cert = NULL;
   	char cert_subject_rsa[1024];
    const unsigned char *p = (unsigned char*)cert_chain->entries[ROOT_ATT_CERT_INDEX].data;
    size_t cert_len = cert_chain->entries[ROOT_ATT_CERT_INDEX].data_length;

	DMSG("%s %d", __func__, __LINE__);

    cert = (mbedtls_x509_crt*)TEE_Malloc( sizeof( mbedtls_x509_crt ), TEE_MALLOC_FILL_ZERO );
    if( cert == NULL )
        return TEE_ERROR_OUT_OF_MEMORY;

    mbedtls_x509_crt_init( cert );

	DMSG("root certificate: \n");
	DHEXDUMP(p,cert_len);

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
				key_usage,rsa_attest_cert, attest_ext, cert_subject_rsa );
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
						unsigned int key_usage,
						keymaster_cert_chain_t *cert_chain,
						keymaster_blob_t *attest_ext)
{
	int ret;
	TEE_Result res = TEE_SUCCESS;
	keymaster_blob_t *ecc_attest_cert = &cert_chain->entries[KEY_ATT_CERT_INDEX];
	mbedtls_pk_context issuer_key = {NULL,NULL};
	mbedtls_pk_context subject_key = {NULL,NULL};
	mbedtls_x509_crt *cert = NULL;
   	char cert_subject_ecc[1024];
    const unsigned char *p = (unsigned char*)cert_chain->entries[ROOT_ATT_CERT_INDEX].data;
    size_t cert_len = cert_chain->entries[ROOT_ATT_CERT_INDEX].data_length;

	DMSG("%s %d", __func__, __LINE__);

    cert = (mbedtls_x509_crt*)TEE_Malloc( sizeof( mbedtls_x509_crt ), TEE_MALLOC_FILL_ZERO );
    if( cert == NULL )
        return TEE_ERROR_OUT_OF_MEMORY;

    mbedtls_x509_crt_init( cert );

	DMSG("root certificate: \n");
	DHEXDUMP(p,cert_len);

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
				key_usage,ecc_attest_cert, attest_ext, cert_subject_ecc );
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

keymaster_error_t mbedTLS_encode_ec_sign(uint8_t *out, uint32_t *out_l) {
	keymaster_error_t ret = KM_ERROR_UNKNOWN_ERROR;
	uint32_t r_size = *out_l / 2;
	uint32_t s_size = *out_l / 2;
	mbedtls_mpi r, s;
	unsigned char buf[MBEDTLS_ECDSA_MAX_LEN];
	unsigned char *p = buf + sizeof( buf );
	int len = 0;
	int total_len = 0;

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	if (mbedtls_mpi_read_binary(&r, out, r_size) ||
	    mbedtls_mpi_read_binary(&s, out + r_size, s_size)) {
		EMSG("Failed to read binary signature");
		goto err;
	}

	len = mbedtls_asn1_write_mpi(&p, buf, &s);
	if (len < 0) {
		EMSG("Failed to write S MPI");
		goto err;
	}

	total_len += len;
	len = mbedtls_asn1_write_mpi(&p, buf, &r);
	if (len < 0) {
		EMSG("Failed to write R MPI");
		goto err;
	}

	total_len += len;
	len = mbedtls_asn1_write_len(&p, buf, (size_t)total_len);
	if (len < 0) {
		EMSG("Failed to write asn1 buffer");
		goto err;
	}

	total_len += len;
	len = mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED |
					       MBEDTLS_ASN1_SEQUENCE);
	if (len < 0) {
		EMSG("Failed to write ASN1 tags");
		goto err;
	}

	total_len += len;
	TEE_MemMove(out, p, (uint32_t)total_len);
	*out_l = (uint32_t)total_len;
	ret = KM_ERROR_OK;

err:
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);

	return ret;
}

keymaster_error_t mbedTLS_decode_ec_sign(keymaster_blob_t *sig,
					 uint32_t key_size) {
	keymaster_error_t ret = KM_ERROR_VERIFICATION_FAILED;
	unsigned char *p = (unsigned char *)sig->data;
	const unsigned char *end = sig->data + sig->data_length;
	size_t len, slen, rlen;
	mbedtls_mpi r, s;

	/* We need key syze in bytes. */
	key_size = (key_size + 7) / 8;

	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);
	if (mbedtls_asn1_get_tag(&p, end, &len,
				 MBEDTLS_ASN1_CONSTRUCTED |
				 MBEDTLS_ASN1_SEQUENCE )) {
		EMSG("Failed to get ASN1 tag");
		goto err;
	}

	if( p + len != end ) {
	    EMSG("Signature decoding failed");
	    goto err;
	}

	if(mbedtls_asn1_get_mpi(&p, end, &r) ||
	   mbedtls_asn1_get_mpi(&p, end, &s)) {
	    EMSG("Failed to get bignums from integers of ec signature");
	    goto err;
	}

	/*
	 * R and S are expected to be the same size as key (in bytes).
	 * Thise numbers are calculated using pseudo-random values (rfc6979),
	 * and sometimes it hapens that one of that values have key_szie-1 lengh
	 * byte array representation (513 bits, for example). In that case
	 * mbedtls returns actual bytes count to represent this value as byte
	 * array. (65 instead of expected 66 for 513-bit values). We can not
	 * leave it as is, because libtomcrypt crypto_acipher_ecc_verify(..)
	 * routine expects that signature is exactly 2x(key_size) bytes length.
	 * Otherwise it triggers TEE_Panic(TEE_ERROR_BAD_PARAMETERS).
	 */

	rlen = mbedtls_mpi_size(&r);
	if (rlen > key_size) {
		EMSG("R can not be larger than key");
		goto err;
	}

	rlen = key_size;

	slen = mbedtls_mpi_size(&s);
	if (slen > key_size) {
		EMSG("S can not be larger than key");
		goto err;
	}
	slen = key_size;


	if (mbedtls_mpi_write_binary(&r, sig->data, rlen) ||
	    mbedtls_mpi_write_binary(&s, sig->data + rlen, slen)) {
		EMSG("Failed to export bignum data to buffer");
		goto err;
	}

	sig->data_length = rlen + slen;
	ret = KM_ERROR_OK;
err:
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&s);

	return ret;
}
