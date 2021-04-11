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
#define ASN1_BUF_LEN_DEFAULT 2048

#define REP_TAG_MAX_VALUES 10
#define MBEDTLS_ASN1_RAW_DATA 0
#define KEYMASTER_VERSION 3
#define ATTESTATION_VERSION 2
#define TIME_STRLEN 15

#define MBEDTLS_OID_ATTESTATION "\x2B\x06\x01\x04\x01\xD6\x79\x02\x01\x11"

#include <printk.h>

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

enum SecurityLevel {
	Software = 0,
	TrustedEnvironment,
};

enum BootState {
	Verified = 0,
	SelfSigned,
	Unverified,
	Failed
};

/* Stubs for hash values used in RottOfTrust */
//TODO: calculate real values
static uint8_t key_stub [32] = {
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa };

static uint8_t unique_id_stub[16] = {
        0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
        0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb
};

static unsigned int add_key_usage(keymaster_key_param_set_t *params)
{
	unsigned int key_usage = 0;

	for (size_t i = 0; i < params->length; i++) {
		if (params->params[i].tag != KM_TAG_PURPOSE)
			continue;

		switch (params->params[i].key_param.enumerated) {
		case KM_PURPOSE_SIGN:
		case KM_PURPOSE_VERIFY:
			key_usage |= MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
			break;
		case KM_PURPOSE_ENCRYPT:
		case KM_PURPOSE_DECRYPT:
			key_usage |= MBEDTLS_X509_KU_KEY_ENCIPHERMENT |
			             MBEDTLS_X509_KU_DATA_ENCIPHERMENT;
			break;
		default:
			break;
		}

	}

	return key_usage;
}

/* entropy source */
static int f_rng(void *rng __unused, unsigned char *output, size_t output_len) {
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

/*
 * Adapted from
 * https://github.com/sidsingh78/EPOCH-to-time-date-converter
 */
static keymaster_error_t convert_epoch_to_date_str(uint32_t sec,
						   unsigned char *t_str,
						   size_t t_strlen)
{
	static unsigned char month_days[12] = {31, 28, 31, 30, 31, 30, 31, 31,
					       30, 31, 30, 31};
	static unsigned char week_days[7] = {4, 5, 6, 0, 1, 2, 3};
	/* Thu=4, Fri=5, Sat=6, Sun=0, Mon=1, Tue=2, Wed=3 */

	unsigned char ntp_hour = 0;
	unsigned char ntp_minute = 0;
	unsigned char ntp_second = 0;
	unsigned char ntp_week_day = 0;
	unsigned char ntp_date = 0;
	unsigned char ntp_month = 0;
	unsigned char leap_days = 0;
	unsigned char leap_year_ind = 0;

	uint16_t temp_days = 0;

	uint32_t epoch = sec;
	uint32_t ntp_year = 0;
	uint32_t days_since_epoch  = 0;
	uint32_t day_of_year = 0;

	uint32_t i = 0;

	if (!t_str) {
		EMSG("Invalid buffer!");
		return KM_ERROR_UNEXPECTED_NULL_POINTER;
	}

	if (t_strlen < TIME_STRLEN) {
		EMSG("Short buffer!");
		return KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
	}

	/*
	 * Add or subtract time zone here.
	 * e.g. GMT +5:30 = +19800 seconds
	 * epoch += 19800;
	 */

	ntp_second = epoch % 60;
	epoch /= 60;
	ntp_minute = epoch % 60;
	epoch /= 60;
	ntp_hour  = epoch % 24;
	epoch /= 24;

	/* number of days since epoch */
	days_since_epoch = epoch;
	/* Calculating WeekDay */
	ntp_week_day = week_days[days_since_epoch % 7];

	/* ball parking year, may not be accurate! */
	ntp_year = 1970 + (days_since_epoch / 365);

	/* Calculating number of leap days since epoch/1970 */
	for (i = 1972; i < ntp_year; i += 4)
		if (((i % 4 == 0) && (i % 100 != 0)) || (i % 400 == 0))
			leap_days++;

	/*
	 * Calculating accurate current year by
	 * (days_since_epoch - extra leap days)
	 */
	ntp_year = 1970 + ((days_since_epoch - leap_days) / 365);
	day_of_year = ((days_since_epoch - leap_days) % 365) + 1;

	if (((ntp_year % 4 == 0) && (ntp_year % 100 != 0)) ||
	    (ntp_year % 400 == 0)) {
		/* February = 29 days for leap years */
		month_days[1] = 29;
		/* if current year is leap, set indicator to 1 */
		leap_year_ind = 1;
	} else {
		/* February = 28 days for non-leap years */
		month_days[1] = 28;
	}

	/* calculating current Month */
	for (ntp_month = 0; ntp_month <= 11; ntp_month++) {
		if (day_of_year <= temp_days)
			break;
		temp_days = temp_days + month_days[ntp_month];
	}

	/* calculating current Date */
	temp_days = temp_days - month_days[ntp_month-1];
	ntp_date = day_of_year - temp_days;

	memset(t_str, 0, TIME_STRLEN);
	/*
	 * snprintf appends a null char at the end so +1 to str len required
	 * e.g. str len required for year is 4, so sprintf with size of 4+1=5
	 * and str len required for hour is 2, so sprintf with size of 2+1=3
	 */
	snprintf((char *)t_str, 5, "%04u", ntp_year);
	snprintf((char *)(t_str + 4), 3, "%02u", ntp_month);
	snprintf((char *)(t_str + 6), 3, "%02u", ntp_date);
	snprintf((char *)(t_str + 8), 3, "%02u", ntp_hour);
	snprintf((char *)(t_str + 10), 3, "%02u", ntp_minute);
	snprintf((char *)(t_str + 12), 3, "%02u", ntp_second);

	DMSG("seconds since epoch: %" PRIu32, sec);
	DMSG("Date string: %s", t_str);
	switch (ntp_week_day) {
	case 0:
		DMSG("Sunday");
		break;
	case 1:
		DMSG("Monday");
		break;
	case 2:
		DMSG("Tuesday");
		break;
	case 3:
		DMSG("Wednesday");
		break;
	case 4:
		DMSG("Thursday");
		break;
	case 5:
		DMSG("Friday");
		break;
	case 6:
		DMSG("Saturday");
		break;
	default:
		break;
	}
	if (leap_year_ind) {
		DMSG("%04u is a leap year", ntp_year);
	} else {
		DMSG("%04u is not a leap year", ntp_year);
	}

	return KM_ERROR_OK;
}

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
	uint32_t curve = UNDEFINED;
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
	if (curve == UNDEFINED) {
		EMSG("Failed to get ECC curve nist");
		ret = KM_ERROR_UNSUPPORTED_EC_CURVE;
		goto out;
	}
	DMSG ("key_size = %u", *key_size);

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
	unsigned char dfl_not_before[TIME_STRLEN] = { 0 };
	unsigned char dfl_not_after[TIME_STRLEN] = { 0 };
	int blen = CERT_ROOT_MAX_SIZE;
	int ret;
	TEE_Result res = TEE_SUCCESS;
	TEE_Time sys_t = { 0 };

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

	IMSG("########################################################");
	IMSG("# CAUTION:");
	IMSG("# REE time used for root cert generation!");
	IMSG("# This is for development and testing ONLY!");
	IMSG("# Platforms should define CFG_ATTESTATION_PROVISIONING");
	IMSG("# and invoke the KM_SET_ATTESTATION_KEY and");
	IMSG("# KM_APPEND_ATTESTATION_CERT_CHAIN commands to send a");
	IMSG("# verified cert (chain) to secure persistent storage");
	IMSG("# during provisioning!");
	IMSG("########################################################");
	TEE_GetREETime(&sys_t);
	ret = convert_epoch_to_date_str(sys_t.seconds, dfl_not_before,
					sizeof(dfl_not_before));
	if (ret) {
		EMSG("convert_epoch_to_date_str: failed: %#x", ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	/*
	 * a cert is usually valid for 2 years (63072000 seconds)
	 */
	ret = convert_epoch_to_date_str(sys_t.seconds + 63072000,
					dfl_not_after, sizeof(dfl_not_after));
	if (ret) {
		EMSG("convert_epoch_to_date_str: failed: %#x", ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	ret = mbedtls_x509write_crt_set_validity(&crt,
						 (const char *)dfl_not_before,
						 (const char *)dfl_not_after);
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
	TEE_Result res = TEE_ERROR_NOT_SUPPORTED;
	int len;

	if (type == TEE_TYPE_ECDSA_KEYPAIR)
		res = mbedTLS_import_ecc_pk(&pk, *obj_h);
	else if (type == TEE_TYPE_RSA_KEYPAIR)
		res = mbedTLS_import_rsa_pk(&pk, *obj_h);
	else
		EMSG("Unsupported keypair type");

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
	TEE_MemMove(export_data->data, buf + sizeof(buf) - len, (uint32_t)len);

	ret = KM_ERROR_OK;
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
	unsigned char dfl_not_before[TIME_STRLEN] = { 0 };
	unsigned char dfl_not_after[TIME_STRLEN] = { 0 };

	int blen = CERT_ROOT_MAX_SIZE;
	int ret;
	TEE_Result res = TEE_SUCCESS;
	TEE_Time sys_t = { 0 };

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

	IMSG("########################################################");
	IMSG("# CAUTION:");
	IMSG("# REE time used for attestation cert generation!");
	IMSG("# This is for development and testing ONLY!");
	IMSG("# Platforms should define CFG_ATTESTATION_PROVISIONING");
	IMSG("# and invoke the KM_SET_ATTESTATION_KEY and");
	IMSG("# KM_APPEND_ATTESTATION_CERT_CHAIN commands to send a");
	IMSG("# verified cert (chain) to secure persistent storage");
	IMSG("# during provisioning!");
	IMSG("########################################################");
	TEE_GetREETime(&sys_t);
	ret = convert_epoch_to_date_str(sys_t.seconds, dfl_not_before,
					sizeof(dfl_not_before));
	if (ret) {
		EMSG("convert_epoch_to_date_str: failed: %#x", ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	/*
	 * a cert is usually valid for 2 years (63072000 seconds)
	 */
	ret = convert_epoch_to_date_str(sys_t.seconds + 63072000,
					dfl_not_after, sizeof(dfl_not_after));
	if (ret) {
		EMSG("convert_epoch_to_date_str: failed: %#x", ret);
		res = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

	ret = mbedtls_x509write_crt_set_validity(&crt,
						 (const char *)dfl_not_before,
						 (const char *)dfl_not_after);
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

TEE_Result mbedTLS_gen_attest_key_cert(TEE_ObjectHandle root_key,
				       TEE_ObjectHandle attest_key,
				       keymaster_algorithm_t alg,
				       unsigned int key_usage,
				       keymaster_cert_chain_t *cert_chain,
				       keymaster_blob_t *attest_ext) {
	int ret;
	TEE_Result res = TEE_SUCCESS;
	keymaster_blob_t *attest_cert = &cert_chain->entries[KEY_ATT_CERT_INDEX];
	mbedtls_x509_crt *cert = NULL;
	mbedtls_pk_context issuer_key = {NULL,NULL};
	mbedtls_pk_context subject_key = {NULL,NULL};
	char cert_subject[1024];
	const unsigned char *p = (unsigned char*)cert_chain->entries[ROOT_ATT_CERT_INDEX].data;
	size_t cert_len = cert_chain->entries[ROOT_ATT_CERT_INDEX].data_length;

	DMSG("%s %d", __func__, __LINE__);

	cert = (mbedtls_x509_crt*)TEE_Malloc(sizeof(mbedtls_x509_crt),
					     TEE_MALLOC_FILL_ZERO);
	if( cert == NULL )
		return TEE_ERROR_OUT_OF_MEMORY;

	mbedtls_x509_crt_init(cert);

	DMSG("root certificate: \n");
	DHEXDUMP(p,cert_len);

	if ((mbedtls_x509_crt_parse_der(cert, p, cert_len)) != 0) {
		EMSG("mbedtls_x509_crt_parse_der: failed");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	ret = mbedtls_x509_dn_gets(cert_subject, sizeof(cert_subject) - 1,
				   &cert->subject);
	if (ret < 0) {
		EMSG("mbedtls_x509_dn_gets: failed: -%#x", -ret);
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	res = (alg == KM_ALGORITHM_RSA) ?
		mbedTLS_import_rsa_pk(&issuer_key, root_key) :
		mbedTLS_import_ecc_pk(&issuer_key, root_key);
	if (res) {
		EMSG("mbedTLS_import_pk for alg %d: failed: %#x", alg, res);
		goto out;
	}

	res = (alg == KM_ALGORITHM_RSA) ?
		mbedTLS_import_rsa_pk(&subject_key, attest_key) :
		mbedTLS_import_ecc_pk(&subject_key, attest_key);
	if (res) {
		EMSG("mbedTLS_import_pk for alg %d: failed: %#x", alg, res);
		goto out;
	}

	res = mbedTLS_attest_key_cert(&issuer_key, &subject_key,
				      key_usage, attest_cert,
				      attest_ext, cert_subject);
	if (res) {
		EMSG("mbedTLS_attest_key_cert: failed: %#x", res);
		goto out;
	}
out:

	mbedtls_pk_free(&issuer_key);
	mbedtls_pk_free(&subject_key);
	mbedtls_x509_crt_free(cert);
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

/**
 * \brief           Writes RootOfTrust to a buffer
 *
 * \note            This function works backwards in data buffer.
 *
 * \param p         Pointer to the array to be populated. If no memory allocated
 *		    - allocation will be processed inside this routine.
 * \param len	    Length of resulting array.
 *
 * \return          0 on success, -1 on failure.
 */
static int asn1_write_rot (uint8_t verified_boot, unsigned char **p,
                           size_t *len) {
	int len_ret = 0, ret;
	unsigned char buf[ASN1_BUF_LEN_DEFAULT];
	unsigned char *ptr = buf + sizeof(buf);
	unsigned char *start = buf;
	//TODO: insert real device lock_state
	int lock_state = 0;

	MBEDTLS_ASN1_CHK_ADD(len_ret, mbedtls_asn1_write_enum(&ptr, start,
	                                                      verified_boot));

	MBEDTLS_ASN1_CHK_ADD(len_ret, mbedtls_asn1_write_bool(&ptr, start,
	                                                      lock_state));

	MBEDTLS_ASN1_CHK_ADD(len_ret,
	                     mbedtls_asn1_write_octet_string(&ptr, start,
	                                                     key_stub,
	                                                     sizeof(key_stub)));

	MBEDTLS_ASN1_CHK_ADD(len_ret, mbedtls_asn1_write_len(&ptr, start,
	                                                     (size_t)len_ret));

	MBEDTLS_ASN1_CHK_ADD(len_ret,
	                     mbedtls_asn1_write_tag(&ptr, start,
	                                            MBEDTLS_ASN1_CONSTRUCTED |
	                                            MBEDTLS_ASN1_SEQUENCE));

	if (!*p) {
		*p = TEE_Malloc((uint32_t)len_ret, TEE_MALLOC_FILL_ZERO);
	}

	if (!*p) {
		EMSG ("Can not populate non-allocated buffer");
		return -1;
	}

	TEE_MemMove(*p, ptr, (uint32_t)len_ret);
	*len = (size_t)len_ret;

	return 0;
}

/**
 * \brief           Writes array of integers to ASN1 SET OF INTEGER
 *
 * \note            This function works backwards in data buffer.
 *
 * \param arr       The integer array to write.
 * \param size      Number of elements in array.
 * \param p	    Pointer to the array to be populated. If no memory allocated
 *		    - allocation will be processed inside this routine.
 * \param len	    Length of resulting array.
 *
 * \return          0 on success, -1 on failure.
  */
static int asn1_write_set_of_int(uint32_t *arr, unsigned long size,
                                 unsigned char **p, uint32_t *len) {
	int ret, len_ret = 0;
	unsigned char buf[ASN1_BUF_LEN_DEFAULT];
	unsigned char *ptr = buf + sizeof(buf);
	unsigned char *start = buf;
	unsigned long count = size;

	while (count > 0) {
		count--;
		MBEDTLS_ASN1_CHK_ADD(len_ret,
		                     mbedtls_asn1_write_int(&ptr, start,
		                                            (int)(arr[count])));
	}

	MBEDTLS_ASN1_CHK_ADD(len_ret, mbedtls_asn1_write_len(&ptr, start,
	                                                     (size_t)len_ret));

	MBEDTLS_ASN1_CHK_ADD(len_ret,
	                     mbedtls_asn1_write_tag(&ptr, start,
	                                            MBEDTLS_ASN1_CONSTRUCTED |
	                                            MBEDTLS_ASN1_SET));

	if (!*p) {
		*p = TEE_Malloc((uint32_t)len_ret, TEE_MALLOC_FILL_ZERO);
	}

	if (!*p) {
		EMSG ("Can not populate non-allocated buffer");
		return -1;
	}

	TEE_MemMove(*p, ptr, (uint32_t)len_ret);
	*len = (uint32_t) len_ret;

	return 0;
}

typedef struct asn1_buf
{
    int context_specific;
    int tag;                /**< ASN1 type, e.g. MBEDTLS_ASN1_UTF8_STRING. */
    size_t len;             /**< ASN1 length, in octets. */
    void *p;                /**< ASN1 data, e.g. in ASCII. */
}
asn1_buf;

typedef struct asn1_sequence
{
	asn1_buf buf;          /**< Buffer containing the given ASN.1 item. */
	struct asn1_sequence *next;    /**< The next entry in the sequence. */
} asn1_sequence;

typedef struct param_enforcement {
	keymaster_key_param_set_t *pars;
	bool hw_enforced;
} param_enforcement;

static struct attestation_tags {
	keymaster_tag_t tag;
	int context;
} auth_tag_list[] = {
        { KM_TAG_ATTESTATION_APPLICATION_ID, 709 },
        { KM_TAG_OS_PATCHLEVEL, 706 },
        { KM_TAG_OS_VERSION, 705 },
        { KM_TAG_ROOT_OF_TRUST, 704 },
        { KM_TAG_ROLLBACK_RESISTANT, 703 },
        { KM_TAG_ORIGIN, 702 },
        { KM_TAG_CREATION_DATETIME, 701 },
        { KM_TAG_APPLICATION_ID, 601 },
        { KM_TAG_ALL_APPLICATIONS, 600 },
        { KM_TAG_ALLOW_WHILE_ON_BODY, 506 },
        { KM_TAG_AUTH_TIMEOUT, 505 },
        { KM_TAG_USER_AUTH_TYPE, 504 },
        { KM_TAG_NO_AUTH_REQUIRED, 503 },
        { KM_TAG_USAGE_EXPIRE_DATETIME, 402 },
        { KM_TAG_ORIGINATION_EXPIRE_DATETIME, 401 },
        { KM_TAG_ACTIVE_DATETIME, 400 },
        { KM_TAG_RSA_PUBLIC_EXPONENT, 200 },
        { KM_TAG_EC_CURVE, 10 },
        { KM_TAG_PADDING, 6 },
        { KM_TAG_DIGEST, 5 },
        { KM_TAG_KEY_SIZE, 3 },
        { KM_TAG_ALGORITHM, 2 },
        { KM_TAG_PURPOSE, 1 },
};

/**
 * @brief		Select params from src param set by a tag and populates
 *			them to	dst.
 *
 * @note		dst is supposed to be an allocated pointer to contain
 *			all possible values of requested tag. Requested blobs
 *			should be released after usage.
 *
 * @warning		In case of requesting blob (KM_BYTES or KM_BIGNUM) - do
 *			free the dst blob.data pointer after using.
 *
 * @param src		Param set to get params from.
 * @param tag		Tag to be selected from all params.
 * @param to		Allocated array of params to be populated.
 * @return		Count of populated tags.
 */
static size_t get_params_by_tag(keymaster_key_param_set_t *src,
                                keymaster_tag_t tag,
                                void *dst) {
	size_t count = 0;

	keymaster_tag_type_t type = keymaster_tag_get_type(tag);
	for (size_t i = 0; i < src->length; i++) {
		if (tag != src->params[i].tag)
			continue;

		count++;

		switch (type) {
			case KM_ENUM: {
				uint32_t *val = dst;
				*val = src->params[i].key_param.enumerated;
				break;
			}
		        case KM_ENUM_REP: {
			        uint32_t *val = dst;
				val[count - 1] = src->params[i].key_param.enumerated;
				break;
		        }

			case KM_UINT: {
				uint32_t *val = dst;
				*val = src->params[i].key_param.integer;
				break;
			}
		        case KM_UINT_REP: {
			        uint32_t *val = dst;
				val[count - 1] = src->params[i].key_param.integer;
				break;
		        }

			case KM_ULONG: {
				uint64_t *val = dst;
				*val = src->params[i].key_param.long_integer;
				break;
			}
		        case KM_ULONG_REP: {
			        uint64_t *val = dst;
				val[count - 1] = src->params[i].key_param.long_integer;
				break;
		        }

		        case KM_DATE: {
			        uint64_t *val = dst;
				*val = src->params[i].key_param.date_time;
				break;
		        }

		        case  KM_BOOL: {
			        bool *val = dst;
				*val = src->params[i].key_param.boolean;
				break;
		        }

		        case KM_BIGNUM:
		        case KM_BYTES: {
			        keymaster_blob_t blob;
				keymaster_blob_t *val = dst;
				blob.data_length = src->params[i].key_param.
				                   blob.data_length;
				blob.data = TEE_Malloc((uint32_t)blob.data_length,
				                        TEE_MALLOC_FILL_ZERO);

				if (!blob.data) {
					EMSG("Failed to allocate memory");
					return 0;
				}

				memcpy(blob.data, src->params[i].key_param.blob.data,
				       blob.data_length);

				*val = blob;
				break;
		        }

		        default:
			        return 0;
		}
	}

	return count;
}

static size_t extract_param(param_enforcement *params,
                            size_t len,
                            keymaster_tag_t tag,
                            void *tag_val,
                            bool *is_hw) {
	size_t i, ret = 0;

	for (i = 0; i <len; i++) {
		ret = get_params_by_tag(params[i].pars, tag, tag_val);
		if (ret > 0) {
			*is_hw = params[i].hw_enforced;
			break;
		}
	}

	return ret;
}

/**
 * \brief          Adds data to ASN1 SEQUENCE
 *
 * \note	   All blobs will NOT be copied while adding to sequence.
 *		   In case of releasing sequence memory by asn1_sequence_free
 *		   all blobs will be released.
 *
 * \param dst      Target sequence to be expanded.
 * \param p        ASN1 data, e.g. in ASCII.
 * \param tag      ASN1 type, e.g. MBEDTLS_ASN1_UTF8_STRING.
 * \param len      ASN1 length, in octets.
 * \return         0 on success, -1 on failure
 */
static int asn1_add_to_sequence(asn1_sequence **dst, void *p,
                                size_t len, keymaster_tag_t tag,
                                int context) {
	mbedtls_mpi *mpi;
	keymaster_tag_type_t type = keymaster_tag_get_type(tag);
	asn1_sequence *cur = TEE_Malloc(sizeof(asn1_sequence),
	                                        TEE_MALLOC_FILL_ZERO);
	asn1_sequence *seq;

	if (!cur) {
		EMSG("failed to allocate memory");
		return -1;
	}

	cur->buf.context_specific = context;
	cur->next = NULL;

	seq = *dst;

	if (!seq) {
		*dst = cur;
		seq = *dst;
	}
	else {
		while (seq->next != NULL) {
			seq = seq->next;
		}

		seq->next = cur;
	}

	switch (type) {
	        case KM_BIGNUM:
	        case KM_BYTES: {
		        keymaster_blob_t *blob = (keymaster_blob_t*)p;
			cur->buf.len = blob->data_length;
			cur->buf.p = blob->data;
			if (tag == KM_TAG_ROOT_OF_TRUST)
				cur->buf.tag = MBEDTLS_ASN1_RAW_DATA;
			else
				cur->buf.tag = MBEDTLS_ASN1_OCTET_STRING;
			return 0;
	        }

	        case KM_UINT_REP:
	        case KM_ENUM_REP: {
		        cur->buf.tag = MBEDTLS_ASN1_RAW_DATA;
			uint32_t tlen;
			unsigned char *ptr = NULL;
			if (asn1_write_set_of_int(p, len, &ptr, &tlen)) {
				EMSG("Failed to add tag %s value to sequence.",
				     TA_tag_to_str(tag));
				goto err;
			}

			cur->buf.p = ptr;
			cur->buf.len = (size_t)tlen;
			return 0;
		}

	        case KM_BOOL: {
			cur->buf.len = sizeof(bool);
			cur->buf.tag = MBEDTLS_ASN1_BOOLEAN;
			cur->buf.p = TEE_Malloc((uint32_t)cur->buf.len,
			                        TEE_MALLOC_FILL_ZERO);
			if (!cur->buf.p) {
				EMSG("Failed to allocate memory");
				goto err;
			}

			memcpy(cur->buf.p, &p, cur->buf.len);
			return 0;
		}

	        case KM_DATE:
	        case KM_ULONG: {
			uint64_t *val = p;
			*val = TEE_U64_BSWAP(*val);
			cur->buf.len = sizeof(uint64_t);
			cur->buf.tag = MBEDTLS_ASN1_INTEGER;
			break;
		}

	        case KM_UINT:
	        case KM_ENUM: {
			uint32_t *val = p;
			*val = TEE_U32_BSWAP(*val);
			cur->buf.len = sizeof(uint32_t);
			cur->buf.tag = MBEDTLS_ASN1_INTEGER;
			break;
		}

	        default:
			break;
	}

	/* Process KM_DATE, KM_ULONG, KM_UINT and KM_ENUM as MPIs. */
	mpi = TEE_Malloc(sizeof(mbedtls_mpi), TEE_MALLOC_FILL_ZERO);

	if (!mpi) {
		EMSG("Faield to allocate memory");
		goto err;
	}

	mbedtls_mpi_init(mpi);

	if (mbedtls_mpi_read_binary(mpi, p, cur->buf.len)) {
		EMSG("Faield to read mpi");
		goto err;
	}

	cur->buf.p = (unsigned char*)mpi;

	return 0;

err:
	TEE_Free(cur);
	seq->next = NULL;
	return -1;
}

static void asn1_sequence_release(asn1_sequence **dst) {
	asn1_sequence *seq = *dst;
	while (seq) {
		asn1_sequence *cur = seq;
		seq = seq->next;
		if (cur->buf.tag == MBEDTLS_ASN1_INTEGER) {
			mbedtls_mpi *mpi = (mbedtls_mpi *) cur->buf.p;
			mbedtls_mpi_free(mpi);
		}

		TEE_Free(cur->buf.p);
		TEE_Free(cur);
	}
}

/**
 * ITU-T X.690 (08/2015)
 * 8.1.2.4
 */
static int mbedtls_asn1_write_int_tag(unsigned char **p,
                                      unsigned char *start, int value)
{
	size_t len = 0;
	int counter = 0;
	unsigned char tag_mask = MBEDTLS_ASN1_TAG_VALUE_MASK |
	                         MBEDTLS_ASN1_CONSTRUCTED |
	                         MBEDTLS_ASN1_CONTEXT_SPECIFIC;

	if (value >= 31) {
		int ret;

		while (value > 0) {
			if (*p - start < 1)
				return(MBEDTLS_ERR_ASN1_BUF_TOO_SMALL);

			len += 1;
			*--(*p) = (value & 0x7f) | 0x80;

			value >>= 7;
			if (!counter)
				**p ^= 0x80;
			counter++;
		}

		ret = mbedtls_asn1_write_tag(p, start, tag_mask);
		if (ret < 0) {
			EMSG("Failed to write asn1 tag");
			return ret;
		}

		len += (size_t)ret;
	}
	else {
		unsigned char tag = MBEDTLS_ASN1_CONSTRUCTED |
		MBEDTLS_ASN1_CONTEXT_SPECIFIC | (unsigned char) value;
		len = (size_t)mbedtls_asn1_write_tag(p, start, tag);
	}

	return((int)len);
}


static int write_asn1_sequence(unsigned char**p, unsigned char *start,
                               asn1_sequence *seq) {
	int len_total = 0;
	int ret = 0;
	while(seq) {
		int len_ret = 0;

		switch (seq->buf.tag) {
		        case MBEDTLS_ASN1_OCTET_STRING: {
			        len_ret = mbedtls_asn1_write_octet_string(p,
				                                start,
				                                seq->buf.p,
				                                seq->buf.len);
				break;
		        }

		        case MBEDTLS_ASN1_RAW_DATA : {
			        len_ret = mbedtls_asn1_write_raw_buffer(p,
				                              start,
				                              seq->buf.p,
				                              seq->buf.len);
				break;
		        }

		        case MBEDTLS_ASN1_BOOLEAN: {
				len_ret = mbedtls_asn1_write_null(p, start);
				break;
		        }

		        case MBEDTLS_ASN1_INTEGER: {
			        mbedtls_mpi *mpi = (mbedtls_mpi *)seq->buf.p;
				len_ret = mbedtls_asn1_write_mpi(p, start, mpi);
				break;

		        }
		        default:
			        break;
		}

		if (len_ret <= 0) {
			EMSG ("Failed to write tag %d with context"
			      "%d", seq->buf.tag, seq->buf.context_specific);
			return -1;
		}

		len_total += len_ret;
		len_ret = mbedtls_asn1_write_len(p, start, (size_t)len_ret);
		if (len_ret <= 0) {
			EMSG("Failed to write length");
			return -1;
		}

		len_total += len_ret;
		len_ret = mbedtls_asn1_write_int_tag(p, start,
		                                     seq->buf.context_specific);
		if (len_ret <= 0) {
			EMSG("Failed to write context specific tag");
			return -1;
		}

		len_total += len_ret;
		seq = seq->next;
	}

	MBEDTLS_ASN1_CHK_ADD(len_total, mbedtls_asn1_write_len(p, start,
	                                                     (size_t)len_total));

	MBEDTLS_ASN1_CHK_ADD(len_total,
	                     mbedtls_asn1_write_tag(p, start,
	                                            MBEDTLS_ASN1_CONSTRUCTED |
	                                            MBEDTLS_ASN1_SEQUENCE));

	return len_total;
}

static int write_authorization_lists(keymaster_key_characteristics_t *chr,
                                     keymaster_key_param_set_t *attest_params,
                                     uint8_t verified_boot, unsigned char**p,
                                     unsigned char *start) {
	size_t i = 0;
	asn1_sequence *sw_auth_seq = NULL, *hw_auth_seq = NULL;
	bool is_hw = true;
	int ret = 0, len_ret = 0;

	param_enforcement params [] = {
		{ &chr->sw_enforced,  false },
		{ &chr->hw_enforced,  true },
	        { attest_params, false }
	};

	for (i = 0; i < sizeof(auth_tag_list) / sizeof(auth_tag_list[0]); i++) {
		/* Buffers to store possible tag values */
		bool bool_par = true;
		uint32_t uint_par = 0;
		uint64_t long_par = 0;
		uint32_t rep_par[REP_TAG_MAX_VALUES];
		keymaster_blob_t blob_par = EMPTY_BLOB;
		void *par_ptr = NULL;

		size_t par_count = 0;

		keymaster_tag_type_t type =
		                keymaster_tag_get_type(auth_tag_list[i].tag);

		if (auth_tag_list[i].tag == KM_TAG_ROOT_OF_TRUST) {
			keymaster_blob_t rot = EMPTY_BLOB;
			if (asn1_write_rot(verified_boot,
			                   &rot.data, &rot.data_length)) {
			        EMSG("Failed to write RootOfTrust.");
			        /* Continue the loop. ROT will be skipped. */
				continue;
			}

			if (asn1_add_to_sequence(&hw_auth_seq, &rot, 1,
						 auth_tag_list[i].tag,
						 auth_tag_list[i].context)) {
				EMSG("Can not ROT tag to sequence!");
				/* Continue the loop */
			}

			continue;
		}

		switch (type) {
	                case KM_ENUM:
	                case KM_UINT: {
			        par_ptr = &uint_par;
			        break;
		        }

	                case KM_ENUM_REP:
	                case KM_UINT_REP: {
			        par_ptr = rep_par;
			        break;
		        }

	                case KM_ULONG:
	                case KM_DATE: {
			        par_ptr = &long_par;
			        break;
		        }

	                case  KM_BOOL: {
			        par_ptr = &bool_par;
			        break;
		        }

	                case KM_BIGNUM:
	                case KM_BYTES: {
			        par_ptr = &blob_par;
			        break;
		        }

	                default:
			        break;
		}

		par_count = extract_param(params,
			                  sizeof(params)/sizeof(params[0]),
		                          auth_tag_list[i].tag, par_ptr, &is_hw);

		if (!par_count)
			continue;

		DMSG ("Tag %s, count = %zu, HW_ENFORCED = %d",
		      TA_tag_to_str(auth_tag_list[i].tag), par_count,
		      is_hw);

		asn1_sequence **seq = is_hw ? &hw_auth_seq :
		                              &sw_auth_seq;

		if (asn1_add_to_sequence(seq, par_ptr, par_count,
		                         auth_tag_list[i].tag,
		                         auth_tag_list[i].context)) {
			EMSG("Can not add tag to sequence!");
			/* Continue the loop */
		}
	}

	ret = write_asn1_sequence(p, start, hw_auth_seq);
	if (ret < 0) {
		EMSG("Failed to serialize asn1 hw sequence");
		goto out;
	}

	len_ret += ret;

	ret = write_asn1_sequence(p, start, sw_auth_seq);
	if (ret < 0) {
		EMSG("Failed to serialize asn1 sw sequence");
		goto out;
	}

	len_ret += ret;

out:
	asn1_sequence_release(&hw_auth_seq);
	asn1_sequence_release(&sw_auth_seq);

	return ret < 0 ? ret : len_ret;
}

static keymaster_error_t mbedTLS_gen_att_extension(keymaster_key_characteristics_t *chr,
                                                   keymaster_key_param_set_t *attest_params,
                                                   uint8_t verified_boot,
                                                   bool includeUniqueID,
                                                   keymaster_blob_t *ext) {
	int ret = 0;
	keymaster_blob_t challenge = EMPTY_BLOB;
	int len_ret = 0;
	unsigned char buf[4096];
	unsigned char *start = buf;
	unsigned char *p = start + sizeof(buf);

	MBEDTLS_ASN1_CHK_ADD(len_ret,
	                     write_authorization_lists(chr, attest_params,
	                                               verified_boot, &p,
	                                               start));

	if (includeUniqueID)
	{
		MBEDTLS_ASN1_CHK_ADD(len_ret,
		                     mbedtls_asn1_write_octet_string(&p, start,
		                                                         unique_id_stub,
		                                                         sizeof(unique_id_stub)));
	} else {
		MBEDTLS_ASN1_CHK_ADD(len_ret,
		                     mbedtls_asn1_write_octet_string(&p, start,
		                                                         unique_id_stub,
		                                                         0));
	}

	if (get_params_by_tag(attest_params, KM_TAG_ATTESTATION_CHALLENGE,
	                      &challenge)) {
		MBEDTLS_ASN1_CHK_ADD(len_ret,
		                     mbedtls_asn1_write_octet_string(&p, start,
		                                                     challenge.data,
		                                                     challenge.data_length));
		TEE_Free(challenge.data);
	}

	MBEDTLS_ASN1_CHK_ADD(len_ret,
	                     mbedtls_asn1_write_enum(&p, start,
	                                                 TrustedEnvironment));

	MBEDTLS_ASN1_CHK_ADD(len_ret, mbedtls_asn1_write_int(&p, start,
	                                                     KEYMASTER_VERSION));

	MBEDTLS_ASN1_CHK_ADD(len_ret,
	                     mbedtls_asn1_write_enum(&p, start,
	                                                 TrustedEnvironment));

	MBEDTLS_ASN1_CHK_ADD(len_ret, mbedtls_asn1_write_int(&p, start,
	                                                     ATTESTATION_VERSION));

	MBEDTLS_ASN1_CHK_ADD(len_ret, mbedtls_asn1_write_len(&p, start,
	                                                     (uint32_t)len_ret));

	MBEDTLS_ASN1_CHK_ADD(len_ret,
	                     mbedtls_asn1_write_tag(&p, start,
	                                            MBEDTLS_ASN1_CONSTRUCTED |
	                                            MBEDTLS_ASN1_SEQUENCE));

	ext->data = TEE_Malloc((uint32_t)len_ret, TEE_MALLOC_FILL_ZERO);
	if (!ext->data) {
		EMSG("Failed to allocate memory");
		return KM_ERROR_MEMORY_ALLOCATION_FAILED;
	}

	TEE_MemMove(ext->data, p, (uint32_t)len_ret);

	ext->data_length = (size_t)len_ret;


	return KM_ERROR_OK;
}

TEE_Result TA_gen_attest_cert(TEE_ObjectHandle attestedKey,
                              keymaster_key_param_set_t *attest_params,
                              keymaster_key_characteristics_t *key_chr,
                              uint8_t verified_boot,
                              bool includeUniqueID,
                              keymaster_algorithm_t alg,
                              keymaster_cert_chain_t *cert_chain)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle rootAttKey = TEE_HANDLE_NULL;
	keymaster_blob_t attest_ext = EMPTY_BLOB;
	unsigned int key_usage = 0;

	//Output certificate
	uint32_t output_certificate_size = ATTEST_CERT_BUFFER_SIZE;

	key_usage = add_key_usage(&key_chr->hw_enforced);

	//Serialize root EC/RSA attestation key (for sign)
	res = alg == KM_ALGORITHM_EC ? TA_open_ec_attest_key(&rootAttKey) :
	                               TA_open_rsa_attest_key(&rootAttKey);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to open root EC attestation key, res=%x", res);
		goto error_1;
	}

	if (mbedTLS_gen_att_extension(key_chr, attest_params, verified_boot,
	                              includeUniqueID, &attest_ext)) {
		res = TEE_ERROR_GENERIC;
		EMSG("Failed to generate attestation extension");
		goto error_1;
	}
	else
		res = TEE_SUCCESS;

	DMSG("attestation extension: \n");
	DHEXDUMP(attest_ext.data,
	         attest_ext.data_length);

	cert_chain->entries[KEY_ATT_CERT_INDEX].data_length = output_certificate_size;
	cert_chain->entries[KEY_ATT_CERT_INDEX].data = TEE_Malloc(output_certificate_size, TEE_MALLOC_FILL_ZERO);
	if (cert_chain->entries[KEY_ATT_CERT_INDEX].data == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		EMSG("Failed to allocate memory for attest certificate output");
		goto error_1;
	}

	res = mbedTLS_gen_attest_key_cert(rootAttKey,
	                                  attestedKey,
	                                  alg,
	                                  key_usage,
	                                  cert_chain,
	                                  &attest_ext);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to generate key attestation, res=%x", res);
		goto error_1;
	}

	DMSG("mbedTLS certificate: \n");
	DHEXDUMP(cert_chain->entries[KEY_ATT_CERT_INDEX].data,
	         cert_chain->entries[KEY_ATT_CERT_INDEX].data_length);

error_1:
	TA_close_attest_obj(rootAttKey);
	TEE_Free(attest_ext.data);

	return res;
}
