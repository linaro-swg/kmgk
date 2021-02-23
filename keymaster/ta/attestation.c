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

#include "attestation.h"
#include "generator.h"
#include "mbedtls_proxy.h"
#include "crypto_aes.h"

//Attestation root keys - RSA and EC
static uint8_t RsaAttKeyID[] = {0xb7U, 0x6aU, 0xb0U, 0xdcU};
static uint8_t EcAttKeyID[] = {0xf2U, 0xa0U, 0x37U, 0x80U};
//Root attestation certificates
static uint8_t RSARootAttCertID[] = {0xaeU, 0xc9U, 0x07U, 0x28U};
static uint8_t ECRootAttCertID[] = {0x74U, 0xf4U, 0xa6U, 0x84U};

#ifdef ENUM_PERS_OBJS
void TA_enum_attest_objs(void)
{
	TEE_ObjectEnumHandle objectEnumerator = TEE_HANDLE_NULL;
	TEE_ObjectInfo objInfo;
	uint8_t objectID[64];
	uint32_t objectIDLen = 64;

	DMSG("Enumerate persistent objects!");
	res = TEE_AllocatePersistentObjectEnumerator(&objectEnumerator);
	if (res == TEE_SUCCESS) {
		res = TEE_StartPersistentObjectEnumerator(objectEnumerator,
				TEE_STORAGE_PRIVATE);
		if (res == TEE_SUCCESS) {
			while (TEE_GetNextPersistentObject(objectEnumerator, &objInfo,
					objectID, &objectIDLen) == TEE_SUCCESS) {
				DMSG("OBJ:%d|%x|%d|%d|%d|%d", objectIDLen, objInfo.objectType,
						objInfo.keySize, objInfo.maxKeySize, objInfo.dataSize,
						objInfo.dataPosition);
			}
		}
		TEE_FreePersistentObjectEnumerator(objectEnumerator);
	}
}
#endif

#ifdef WIPE_PERS_OBJS
void TA_wipe_attest_objs(void)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ |
			TEE_DATA_FLAG_ACCESS_WRITE |
			TEE_DATA_FLAG_ACCESS_WRITE_META |
			TEE_DATA_FLAG_SHARE_READ |
			TEE_DATA_FLAG_SHARE_WRITE;
	DMSG("Wipe persistent objects!");
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
			RsaAttKeyID, sizeof(RsaAttKeyID),
				flags, &object);
	if (res == TEE_SUCCESS) {
		TEE_CloseAndDeletePersistentObject1(object);
		DMSG("Deleted RSA key!");
	}
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
			EcAttKeyID, sizeof(EcAttKeyID),
				flags, &object);
	if (res == TEE_SUCCESS) {
		TEE_CloseAndDeletePersistentObject1(object);
		DMSG("Deleted EC key!");
	}
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
			RSARootAttCertID, sizeof(RSARootAttCertID),
				flags, &object);
	if (res == TEE_SUCCESS) {
		TEE_CloseAndDeletePersistentObject1(object);
		DMSG("Deleted RSA cert!");
	}
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
			ECRootAttCertID, sizeof(ECRootAttCertID),
				flags, &object);
	if (res == TEE_SUCCESS) {
		TEE_CloseAndDeletePersistentObject1(object);
		DMSG("Deleted EC cert!");
	}
}
#endif

TEE_Result TA_open_rsa_attest_key(TEE_ObjectHandle *rsaKey)
{
	TEE_Result res = TEE_SUCCESS;
	DMSG("Open RSA root attestation key");
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
			RsaAttKeyID, sizeof(RsaAttKeyID),
			TEE_DATA_FLAG_ACCESS_READ, rsaKey);
	if (res == TEE_SUCCESS) {
		DMSG("RSA root attestation key successfully opened");
	} else if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		DMSG("RSA persistent key does not exist");
	} else {
		EMSG("Failed to open a RSA persistent key, res=%x", res);
	}
	return res;
}

TEE_Result TA_open_ec_attest_key(TEE_ObjectHandle *ecKey)
{
	TEE_Result res = TEE_SUCCESS;
	DMSG("Open EC root attestation key");
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
			EcAttKeyID, sizeof(EcAttKeyID),
			TEE_DATA_FLAG_ACCESS_READ, ecKey);
	if (res == TEE_SUCCESS) {
		DMSG("EC root attestation key successfully opened");
	} else if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		DMSG("EC persistent key does not exist");
	} else {
		EMSG("Failed to open a EC persistent key, res=%x", res);
	}
	return res;
}

TEE_Result TA_open_root_rsa_attest_cert(TEE_ObjectHandle *attCert)
{
	TEE_Result res = TEE_SUCCESS;
	DMSG("Open root RSA attestation certificate");
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
			RSARootAttCertID, sizeof(RSARootAttCertID),
			TEE_DATA_FLAG_ACCESS_READ, attCert);
	if (res == TEE_SUCCESS) {
		DMSG("RSA root certificate successfully opened");
	} else if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		DMSG("RSA persistent cert does not exist");
	} else {
		EMSG("Failed to open a root RSA persistent certificate, res=%x", res);
	}
	return res;
}

TEE_Result TA_open_root_ec_attest_cert(TEE_ObjectHandle *attCert)
{
	TEE_Result res = TEE_SUCCESS;
	DMSG("Open root EC attestation certificate");
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
			ECRootAttCertID, sizeof(ECRootAttCertID),
			TEE_DATA_FLAG_ACCESS_READ, attCert);
	if (res == TEE_SUCCESS) {
		DMSG("EC root certificate successfully opened");
	} else if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		DMSG("EC persistent cert does not exist");
	} else {
		EMSG("Failed to open a root EC persistent certificate, res=%x", res);
	}
	return res;
}

#ifdef CFG_ATTESTATION_PROVISIONING
static TEE_Result TA_set_rsa_attest_key(keymaster_blob_t key_data)
{
	TEE_Result result = TEE_ERROR_BAD_PARAMETERS;
	TEE_ObjectHandle RSAobject = TEE_HANDLE_NULL;
	TEE_Attribute *attrs = NULL;
	uint32_t attrs_count = 0;
	uint64_t key_rsa_public_exponent = UNDEFINED;
	uint32_t key_size = UNDEFINED;

	DMSG("RSA root attestation key ...");

	if (mbedTLS_decode_pkcs8(key_data, &attrs,
			&attrs_count, KM_ALGORITHM_RSA, &key_size,
			&key_rsa_public_exponent) != KM_ERROR_OK) {
		goto error_1;
	}

	if (key_size % 8 != 0 || key_size > MAX_KEY_RSA) {
		EMSG("RSA key size %d must be multiple of 8 and less than %u",
							key_size,MAX_KEY_RSA);
		goto error_2;
	}

	/*
	 * Create object in storage
	 * Can store this in RPMB by replacing TEE_STORAGE_PRIVATE with
	 * TEE_STORAGE_PRIVATE_RPMB
	 */
	result = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
			RsaAttKeyID, sizeof(RsaAttKeyID),
			TEE_DATA_FLAG_ACCESS_WRITE,
			TEE_HANDLE_NULL, NULL, 0U, &RSAobject);
	if (result != TEE_SUCCESS) {
		EMSG("Failed to create a RSA persistent key, res=%x", result);
		goto error_2;
	}

	for (uint32_t i = 0; i < attrs_count; i++) {
		//Store RSA key in format: size | buffer attribute
		DMSG("attrs[i].attributeID 0x%08X size %d", attrs[i].attributeID, attrs[i].content.ref.length);
		result = TA_write_obj_attr(RSAobject, attrs[i].content.ref.buffer, attrs[i].content.ref.length);
		if (result != TEE_SUCCESS) {
			EMSG("Failed to write RSA attribute %x, res=%x",
					attrs[i].attributeID, result);
			goto error_3;
		}
	}
error_3:
	(result == TEE_SUCCESS) ?
			TEE_CloseObject(RSAobject) :
			TEE_CloseAndDeletePersistentObject(RSAobject);
error_2:
	free_attrs(attrs, attrs_count);

error_1:
	return result;
}

static TEE_Result TA_set_ec_attest_key(keymaster_blob_t key_data)
{
	TEE_Result result = TEE_ERROR_BAD_PARAMETERS;
	TEE_ObjectHandle ECobject = TEE_HANDLE_NULL;
	TEE_Attribute *attrs = NULL;
	uint32_t attrs_count = 0;
	uint64_t key_rsa_public_exponent = UNDEFINED;
	uint32_t key_size = UNDEFINED;
	uint32_t curve = UNDEFINED;

	DMSG("EC root attestation key creation...");

	if (mbedTLS_decode_pkcs8(key_data, &attrs,
			&attrs_count, KM_ALGORITHM_EC, &key_size,
			&key_rsa_public_exponent) != KM_ERROR_OK) {
		goto error_1;
	}

	curve = TA_get_curve_nist(key_size);
	if (curve == UNDEFINED) {
		EMSG("Failed to get ECC curve nist");
		result = TEE_ERROR_BAD_PARAMETERS;
		goto error_2;
	}

	/*
	 * Create object in storage
	 * Can store this in RPMB by replacing TEE_STORAGE_PRIVATE with
	 * TEE_STORAGE_PRIVATE_RPMB
	 */
	result = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
			EcAttKeyID, sizeof(EcAttKeyID),
			TEE_DATA_FLAG_ACCESS_WRITE,
			TEE_HANDLE_NULL, NULL, 0U, &ECobject);
	if (result != TEE_SUCCESS) {
		if (result == TEE_ERROR_ACCESS_CONFLICT)
			EMSG("Key already provisioned");
		EMSG("Failed to create a EC persistent key, res=%x", result);
		goto error_2;
	}

	DMSG("curve 0x%08X", curve);
	result = TEE_WriteObjectData(ECobject,
			(void *)&curve, sizeof(uint32_t));
	if (result != TEE_SUCCESS)
	{
		EMSG("Failed to write Curve value res=%x",
				result);
		goto error_3;
	}

	for (uint32_t i = 0; i < attrs_count; i++) {
		//Attributes are "Ref"
		switch (attrs[i].attributeID) {
		case TEE_ATTR_ECC_PUBLIC_VALUE_X:
		case TEE_ATTR_ECC_PUBLIC_VALUE_Y:
		case TEE_ATTR_ECC_PRIVATE_VALUE:
			DMSG("attrs[i].attributeID 0x%08X size %d", attrs[i].attributeID, attrs[i].content.ref.length);
			result = TA_write_obj_attr(ECobject, attrs[i].content.ref.buffer, attrs[i].content.ref.length);
			if (result != TEE_SUCCESS) {
				EMSG("Failed to write EC attribute %x, res=%x",
						attrs[i].attributeID, result);
				goto error_3;
			}
			break;
		default:
			break;
		}
	}
error_3:
	(result == TEE_SUCCESS) ?
			TEE_CloseObject(ECobject) :
			TEE_CloseAndDeletePersistentObject(ECobject);

error_2:
	free_attrs(attrs, attrs_count);

error_1:
	return result;
}

static TEE_Result TA_append_root_rsa_attest_cert(keymaster_blob_t cert)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle CertObject = TEE_HANDLE_NULL;

	DMSG("Root RSA attestation certificate update...");

	res = TA_open_root_rsa_attest_cert(&CertObject);
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		//Create object in storage
		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
				RSARootAttCertID, sizeof(RSARootAttCertID),
				TEE_DATA_FLAG_ACCESS_WRITE,
				TEE_HANDLE_NULL, NULL, 0U, &CertObject);
	} else if (res == TEE_SUCCESS) {
		//Open object in storage
		TEE_CloseObject(CertObject);
		res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				RSARootAttCertID, sizeof(RSARootAttCertID),
				TEE_DATA_FLAG_ACCESS_WRITE,
				&CertObject);
	}
	if (res != TEE_SUCCESS) {
		EMSG("Failed to create a persistent RSA certificate object, res=%x",
				res);
		goto error_1;
	}
	res = TEE_SeekObjectData(CertObject,0,TEE_DATA_SEEK_END);
	if (res != TEE_SUCCESS) {
		goto error_2;
	}

	//Store cert in format: size | ASN.1 DER buffer
	res = TA_write_obj_attr(CertObject,
				cert.data, cert.data_length);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to write RSA certificate, res=%x", res);
	}

error_2:
	(res == TEE_SUCCESS) ?
			TEE_CloseObject(CertObject) :
			TEE_CloseAndDeletePersistentObject(CertObject);

error_1:
	return res;
}

static TEE_Result TA_append_root_ec_attest_cert(keymaster_blob_t cert)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle CertObject = TEE_HANDLE_NULL;

	DMSG("Root EC attestation certificate creation...");

	res = TA_open_root_ec_attest_cert(&CertObject);
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		//Create object in storage
		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
				ECRootAttCertID, sizeof(ECRootAttCertID),
				TEE_DATA_FLAG_ACCESS_WRITE,
				TEE_HANDLE_NULL, NULL, 0U, &CertObject);
	} else if (res == TEE_SUCCESS) {
		//Open object in storage
		TEE_CloseObject(CertObject);
		res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				ECRootAttCertID, sizeof(ECRootAttCertID),
				TEE_DATA_FLAG_ACCESS_WRITE,
				&CertObject);
	}
	if (res != TEE_SUCCESS) {
		EMSG("Failed to create a persistent EC certificate object, res=%x",
				res);
		goto error_1;
	}
	res = TEE_SeekObjectData(CertObject,0,TEE_DATA_SEEK_END);
	if (res != TEE_SUCCESS) {
		goto error_2;
	}

	//Store cert in format: size | ASN.1 DER buffer
	res = TA_write_obj_attr(CertObject,
				cert.data, cert.data_length);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to write EC certificate, res=%x", res);
	}

error_2:
	(res == TEE_SUCCESS) ?
			TEE_CloseObject(CertObject) :
			TEE_CloseAndDeletePersistentObject(CertObject);

error_1:
	return res;
}

#else // CFG_ATTESTATION_PROVISIONING

static TEE_Result TA_create_rsa_attest_key(void)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle RSAobject = TEE_HANDLE_NULL;
	TEE_ObjectHandle transient_key = TEE_HANDLE_NULL;
	uint32_t *attributes = NULL;
	uint8_t *buffer = NULL;
	uint32_t buffSize = RSA_KEY_BUFFER_SIZE;

	res = TA_open_rsa_attest_key(&RSAobject);
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		//No such key, create it
		DMSG("RSA root attestation key creation...");
		//Allocates an uninitialized transient object
		res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR,
				RSA_KEY_SIZE, &transient_key);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to allocate RSA transient object, res=%x", res);
			goto error_1;
		}
		//Generating an object (default exponent is 65537)
		res = TEE_GenerateKey(transient_key, RSA_KEY_SIZE, NULL, 0);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to generate RSA key, res=%x", res);
			goto error_2;
		}
		//Create object in storage
		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
				RsaAttKeyID, sizeof(RsaAttKeyID),
				TEE_DATA_FLAG_ACCESS_WRITE,
				TEE_HANDLE_NULL, NULL, 0U, &RSAobject);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to create a RSA persistent key, res=%x", res);
			goto error_2;
		}
		//List of RSA attributes
		attributes = TA_get_attrs_list(KM_ALGORITHM_RSA);
		buffer = TEE_Malloc(RSA_KEY_BUFFER_SIZE, TEE_MALLOC_FILL_ZERO);
		if (NULL == buffer) {
			EMSG("Failed to allocate memory for RSA attributes");
			goto error_3;
		}
		//Attributes are "Ref"
		for (uint32_t i = 0; i < KM_ATTR_COUNT_RSA; i++) {
			buffSize = RSA_KEY_BUFFER_SIZE;
			res = TEE_GetObjectBufferAttribute(transient_key, attributes[i],
					buffer, &buffSize);
			if (res != TEE_SUCCESS) {
				EMSG("Failed to get RSA buffer attribute %x, res=%x",
						attributes[i], res);
				goto error_3;
			}

			//Store RSA key in format: size | buffer attribute
			res = TA_write_obj_attr(RSAobject, buffer, buffSize);
			if (res != TEE_SUCCESS) {
				EMSG("Failed to write RSA attribute %x, res=%x",
						attributes[i], res);
				goto error_3;
			}
		}
error_3:
		if (buffer) {
			TEE_Free(buffer);
		}
		(res == TEE_SUCCESS) ?
				TEE_CloseObject(RSAobject) :
				TEE_CloseAndDeletePersistentObject(RSAobject);

error_2:
		if (transient_key != TEE_HANDLE_NULL) {
			TEE_FreeTransientObject(transient_key);
		}

	} else if (res == TEE_SUCCESS) {
		//Key already exits
		DMSG("RSA root attestation key already exits");
		TA_close_attest_obj(RSAobject);
	} else {
		//Something wrong...
		EMSG("Failed to open RSA root attestation key, res=%x", res);
	}

error_1:
	return res;
}

static TEE_Result TA_create_ec_attest_key(void)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle ECobject = TEE_HANDLE_NULL;
	TEE_ObjectHandle transient_key = TEE_HANDLE_NULL;
	uint32_t *attributes = NULL;
	uint8_t *buffer = NULL;
	uint32_t buffSize = EC_KEY_BUFFER_SIZE;
	TEE_Attribute attrs[1];
	uint32_t a = 0, b = 0;

	res = TA_open_ec_attest_key(&ECobject);
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		//No such key, create it
		DMSG("EC root attestation key creation...");
		//Allocates an uninitialized transient object
		res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR,
				EC_KEY_SIZE, &transient_key);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to allocate EC transient object, res=%x", res);
			goto error_1;
		}
		//Generating an object (MUST provide TEE_ATTR_ECC_CURVE)
		TEE_InitValueAttribute(&attrs[0], TEE_ATTR_ECC_CURVE,
				TA_get_curve_nist(EC_KEY_SIZE), 0);
		res = TEE_GenerateKey(transient_key, EC_KEY_SIZE, attrs,
				sizeof(attrs)/sizeof(TEE_Attribute));
		if (res != TEE_SUCCESS) {
			EMSG("Failed to generate EC key, res=%x", res);
			goto error_2;
		}
		//Create object in storage
		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
				EcAttKeyID, sizeof(EcAttKeyID),
				TEE_DATA_FLAG_ACCESS_WRITE,
				TEE_HANDLE_NULL, NULL, 0U, &ECobject);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to create a EC persistent key, res=%x", res);
			goto error_2;
		}
		//List of EC attributes
		attributes = TA_get_attrs_list(KM_ALGORITHM_EC);
		buffer = TEE_Malloc(EC_KEY_BUFFER_SIZE, TEE_MALLOC_FILL_ZERO);
		if (NULL == buffer) {
			EMSG("Failed to allocate memory for EC attributes");
			goto error_3;
		}

		for (uint32_t i = 0; i < KM_ATTR_COUNT_EC; i++) {
			if (is_attr_value(attributes[i])) {
				//Attributes are "Value"
				res = TEE_GetObjectValueAttribute(transient_key,
						attributes[i], &a, &b);
				if (res != TEE_SUCCESS)
				{
					EMSG("Failed to get EC value attribute %x, res=%x",
							attributes[i], res);
					goto error_3;
				}

				res = TEE_WriteObjectData(ECobject,
						(void *)&a, sizeof(uint32_t));
				if (res != TEE_SUCCESS)
				{
					EMSG("Failed to write EC value attribute %x, res=%x",
							attributes[i], res);
					goto error_3;
				}
			} else {
				//Attributes are "Ref"
				buffSize = EC_KEY_BUFFER_SIZE;
				res = TEE_GetObjectBufferAttribute(transient_key,
						attributes[i], buffer, &buffSize);
				if (res != TEE_SUCCESS) {
					EMSG("Failed to get EC buffer attribute %x, res=%x",
							attributes[i], res);
					goto error_3;
				}

				DHEXDUMP(buffer, buffSize);
				//Store EC key in format: size | buffer attribute
				res = TA_write_obj_attr(ECobject, buffer, buffSize);
				if (res != TEE_SUCCESS) {
					EMSG("Failed to write EC attribute %x, res=%x",
							attributes[i], res);
					goto error_3;
				}
			}
		}
error_3:
		if (buffer) {
			TEE_Free(buffer);
		}
		(res == TEE_SUCCESS) ?
				TEE_CloseObject(ECobject) :
				TEE_CloseAndDeletePersistentObject(ECobject);

error_2:
		if (transient_key != TEE_HANDLE_NULL) {
			TEE_FreeTransientObject(transient_key);
		}

	} else if (res == TEE_SUCCESS) {
		//Key already exits
		DMSG("EC root attestation key already exits");
		TA_close_attest_obj(ECobject);
	} else {
		//Something wrong...
		EMSG("Failed to open EC root attestation key, res=%x", res);
	}

error_1:
	return res;
}

static TEE_Result TA_create_root_rsa_attest_cert(void)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle CertObject = TEE_HANDLE_NULL;
	keymaster_blob_t root_cert = {0}; //root RSA certificate
	TEE_ObjectHandle obj_h = TEE_HANDLE_NULL;

	res = TA_open_root_rsa_attest_cert(&CertObject);
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		//No such certificate, create it
		DMSG("Root RSA attestation certificate creation...");
		if (TA_open_rsa_attest_key(&obj_h) != TEE_SUCCESS) {
			EMSG("Failed to open RSA key, res=%x", res);
			goto error_1;
		}
		//Call ASN1 TA to generate root certificate
		res = mbedTLS_gen_root_cert_rsa(obj_h, &root_cert);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to generate RSA root certificate, res=%x", res);
			goto error_2;
		}

		//Create object in storage
		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
				RSARootAttCertID, sizeof(RSARootAttCertID),
				TEE_DATA_FLAG_ACCESS_WRITE,
				TEE_HANDLE_NULL, NULL, 0U, &CertObject);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to create a persistent RSA certificate object, res=%x",
					res);
			goto error_2;
		}

		//Store cert in format: size | ASN.1 DER buffer
		res = TA_write_obj_attr(CertObject,
				root_cert.data,
				(uint32_t)root_cert.data_length);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to write RSA certificate, res=%x", res);
		}

		(res == TEE_SUCCESS) ?
				TEE_CloseObject(CertObject) :
				TEE_CloseAndDeletePersistentObject(CertObject);

error_2:
		if (root_cert.data) {
			TEE_Free(root_cert.data);
		}
		TA_close_attest_obj(obj_h);

	} else if (res == TEE_SUCCESS) {
		//Certificate already exits
		DMSG("Root RSA attestation certificate already exits");
		TA_close_attest_obj(CertObject);
	} else {
		//Something wrong...
		EMSG("Failed to open root RSA attestation certificate, res=%x", res);
	}

error_1:
	return res;
}

static TEE_Result TA_create_root_ec_attest_cert(void)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle CertObject = TEE_HANDLE_NULL;
	keymaster_blob_t root_cert = {0}; //root EC certificate
	TEE_ObjectHandle obj_h = TEE_HANDLE_NULL;

	res = TA_open_root_ec_attest_cert(&CertObject);
	if (res == TEE_ERROR_ITEM_NOT_FOUND) {
		//No such certificate, create it
		DMSG("Root EC attestation certificate creation...");
		if (TA_open_ec_attest_key(&obj_h) != TEE_SUCCESS) {
			EMSG("Failed to open EC key, res=%x", res);
			goto error_1;
		}
		//Call ASN1 TA to generate root certificate
		res = mbedTLS_gen_root_cert_ecc(obj_h, &root_cert);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to generate EC root certificate, res=%x", res);
			goto error_2;
		}

		//Create object in storage
		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
				ECRootAttCertID, sizeof(ECRootAttCertID),
				TEE_DATA_FLAG_ACCESS_WRITE,
				TEE_HANDLE_NULL, NULL, 0U, &CertObject);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to create a persistent EC certificate object, res=%x",
					res);
			goto error_2;
		}

		//Store cert in format: size | ASN.1 DER buffer
		res = TA_write_obj_attr(CertObject,
					root_cert.data,
					(uint32_t)root_cert.data_length);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to write EC certificate, res=%x", res);
		}

		(res == TEE_SUCCESS) ?
				TEE_CloseObject(CertObject) :
				TEE_CloseAndDeletePersistentObject(CertObject);

error_2:
		if (root_cert.data) {
			TEE_Free(root_cert.data);
		}
		TA_close_attest_obj(obj_h);

	} else if (res == TEE_SUCCESS) {
		//Certificate already exits
		DMSG("Root EC attestation certificate already exits");
		TA_close_attest_obj(CertObject);
	} else {
		//Something wrong...
		EMSG("Failed to open root EC attestation certificate, res=%x", res);
	}

error_1:
	return res;
}
#endif

keymaster_error_t TA_read_root_attest_cert(uint32_t type,
				keymaster_cert_chain_t *cert_chain)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle rootAttCert = TEE_HANDLE_NULL;

	if (type == TEE_TYPE_RSA_KEYPAIR) {
		res = TA_open_root_rsa_attest_cert(&rootAttCert);
	} else if (type == TEE_TYPE_ECDSA_KEYPAIR) {
		res = TA_open_root_ec_attest_cert(&rootAttCert);
	}

	if (res != TEE_SUCCESS) {
		EMSG("Failed to open root certificate, res=%x", res);
		goto error;
	}

	//Read root certificate
	res = TA_read_attest_cert(rootAttCert, cert_chain);
	if ((res != TEE_SUCCESS) &&
		(res != TEE_ERROR_SHORT_BUFFER)) {
		EMSG("Failed to read root certificate, res=%x", res);
	}

	TA_close_attest_obj(rootAttCert);

error:
	switch (res)
	{
		case TEE_SUCCESS:
			return KM_ERROR_OK;
		case TEE_ERROR_SHORT_BUFFER:
			return KM_ERROR_INSUFFICIENT_BUFFER_SPACE;
		default:
			return KM_ERROR_UNKNOWN_ERROR;
	}
}

TEE_Result TA_gen_key_attest_cert(uint32_t type,
				  TEE_ObjectHandle attestedKey,
				  keymaster_key_param_set_t *attest_params,
				  keymaster_key_characteristics_t *key_chr,
				  keymaster_cert_chain_t *cert_chain,
				  uint8_t verified_boot,
				  bool includeUniqueID)
{
	TEE_Result res = TEE_SUCCESS;

	if (type == TEE_TYPE_RSA_KEYPAIR) {
		res = TA_gen_attest_cert(attestedKey,
		                         attest_params, key_chr,
		                         verified_boot, includeUniqueID,
		                         KM_ALGORITHM_RSA,
		                         cert_chain);
	} else if (type == TEE_TYPE_ECDSA_KEYPAIR) {
		res = TA_gen_attest_cert(attestedKey,
		                         attest_params, key_chr,
		                         verified_boot, includeUniqueID,
		                         KM_ALGORITHM_EC,
		                         cert_chain);
	} else {
		res = TEE_ERROR_BAD_PARAMETERS;
	}

	if (res != TEE_SUCCESS) {
		EMSG("Failed to generated key certificate, res=%x", res);
	}

	return res;
}

#ifndef CFG_ATTESTATION_PROVISIONING
TEE_Result TA_create_attest_objs(void)
{
	TEE_Result res = TEE_SUCCESS;

	DMSG("%s %d", __func__, __LINE__);

	res = TA_create_rsa_attest_key();
	if (res != TEE_SUCCESS) {
		EMSG("Something wrong with root RSA key, res=%x", res);
		return res;
	}
	res = TA_create_ec_attest_key();
	if (res != TEE_SUCCESS) {
		EMSG("Something wrong with root EC key, res=%x", res);
		return res;
	}
	res = TA_create_root_rsa_attest_cert();
	if (res != TEE_SUCCESS) {
		EMSG("Something wrong with root RSA certificate, res=%x", res);
		return res;
	}
	res = TA_create_root_ec_attest_cert();
	if (res != TEE_SUCCESS) {
		EMSG("Something wrong with root EC certificate, res=%x", res);
		return res;
	}
	return res;
}
#endif

void TA_close_attest_obj(TEE_ObjectHandle attObj)
{
	DMSG("Close attestation object");
	if (attObj != TEE_HANDLE_NULL) {
		TEE_CloseObject(attObj);
	}
}

static uint32_t fetch_length(const uint8_t *in, uint32_t inlen)
{
   uint32_t x, z;

   uint32_t data_offset = 0;

   if (in == NULL) {
      return 0xFFFFFFFF;
   }

   /* skip type and read len */
   if (inlen < 2) {
      return 0xFFFFFFFF;
   }
   ++in; ++data_offset;

   /* read len */
   x = *in++; ++data_offset;

   /* <128 means literal */
   if (x < 128) {
      return x+data_offset;
   }
   x     &= 0x7F; /* the lower 7 bits are the length of the length */
   inlen -= 2;

   /* len means len of len! */
   if (x == 0 || x > 4 || x > inlen) {
      return 0xFFFFFFFF;
   }

   data_offset += x;
   z = 0;
   while (x--) {
      z = (z<<8) | ((uint32_t)*in);
      ++in;
   }
   return z+data_offset;
}

TEE_Result TA_read_attest_cert(TEE_ObjectHandle attObj,
				keymaster_cert_chain_t *cert_chain)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectInfo info = { 0 };
	uint32_t actual_read = 0;
	uint8_t* pBuf = NULL;
	size_t nEntryCount = 1; // KEY_ATT_CERT_INDEX used for key attestation
	uint32_t nCertLen = 0;

	if (cert_chain == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_SeekObjectData(attObj, 0, TEE_DATA_SEEK_SET);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to seek root certificate, res=%x", res);
		return res;
	}

	res = TEE_GetObjectInfo1(attObj, &info);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get certificate info, res=%x", res);
		return res;
	}

	//Read root certificate, index[n], length
	while (info.dataPosition != info.dataSize)
	{
		res = TEE_ReadObjectData(attObj, &nCertLen, sizeof(uint32_t), &actual_read);
		if (res != TEE_SUCCESS || actual_read != sizeof(uint32_t)) {
			EMSG("Failed to read root certificate length, res=%x", res);
			return res;
		}
		nEntryCount++;

		res = TEE_SeekObjectData(attObj, nCertLen, TEE_DATA_SEEK_CUR);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to seek root certificate, res=%x", res);
			return res;
		}

		res = TEE_GetObjectInfo1(attObj, &info);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to get certificate info, res=%x", res);
			return res;
		}
	}

	if (nEntryCount > cert_chain->entry_count)
	{
		cert_chain->entry_count = nEntryCount;
		return TEE_ERROR_SHORT_BUFFER;
	}

	res = TEE_SeekObjectData(attObj, 0, TEE_DATA_SEEK_SET);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to seek root certificate, res=%x", res);
		return res;
	}

	res = TEE_GetObjectInfo1(attObj, &info);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to get certificate info, res=%x", res);
		return res;
	}

	nEntryCount = 1;
	//Read root certificate, index[n], length
	while (info.dataPosition != info.dataSize)
	{
		res = TEE_ReadObjectData(attObj, &nCertLen, sizeof(uint32_t), &actual_read);
		if (res != TEE_SUCCESS || actual_read != sizeof(uint32_t)) {
			EMSG("Failed to read root certificate length, res=%x", res);
			goto error;
		}

		pBuf = TEE_Malloc(nCertLen, TEE_MALLOC_FILL_ZERO);
		if (pBuf == NULL) {
			EMSG("Failed to allocate memory for root certificate data");
			res = KM_ERROR_MEMORY_ALLOCATION_FAILED;
			goto error;
		}

		//Read root certificate, index[n], DER data
		res = TEE_ReadObjectData(attObj, pBuf, nCertLen, &actual_read);
		if (res != TEE_SUCCESS || actual_read != nCertLen) {
			TEE_Free(pBuf);
			EMSG("Failed to read root certificate data, res=%x", res);
			goto error;
		}
		nCertLen = fetch_length(pBuf,nCertLen);

		cert_chain->entries[nEntryCount].data = pBuf;
		cert_chain->entries[nEntryCount].data_length = nCertLen;
		nEntryCount++;

		res = TEE_GetObjectInfo1(attObj, &info);
		if (res != TEE_SUCCESS) {
			EMSG("Failed to get certificate info, res=%x", res);
			goto error;
		}
	}

	return TEE_SUCCESS;
error:
	for (nEntryCount=1;nEntryCount<cert_chain->entry_count;nEntryCount++)
	{
		if (cert_chain->entries[nEntryCount].data != NULL)
		{
			TEE_Free(cert_chain->entries[nEntryCount].data);
			cert_chain->entries[nEntryCount].data_length = 0;
			cert_chain->entries[nEntryCount].data = NULL;
		}
	}
	return res;
}

TEE_Result TA_generate_UniqueID(uint64_t T, uint8_t *appID, uint32_t appIDlen,
		uint8_t R, uint8_t *uniqueID, uint32_t *uniqueIDlen)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key = TEE_HANDLE_NULL;
	uint32_t hmac_length = HMAC_SHA256_KEY_SIZE_BYTE;
	uint8_t hmac_buf[HMAC_SHA256_KEY_SIZE_BYTE];

	if (uniqueID == NULL) {
		EMSG("Invalid UniqueID pointer");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto exit;
	}

	if (*uniqueIDlen < UNIQUE_ID_BUFFER_SIZE) {
		EMSG("Short UniqueID buffer");
		res = TEE_ERROR_SHORT_BUFFER;
		goto exit;
	}

	res = TEE_AllocateOperation(&op, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC,
			HMAC_SHA256_KEY_SIZE_BIT);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to allocate HMAC operation, res=%x", res);
		goto exit;
	}

	res = TA_open_secret_key(&key);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to read secret key, res=%x", res);
		goto free_op;
	}

	res = TEE_SetOperationKey(op, key);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to set secret key, res=%x", res);
		goto free_op;
	}

	TEE_MACInit(op, NULL, 0);
	TEE_MACUpdate(op, &T, sizeof(uint64_t));
	TEE_MACUpdate(op, appID, appIDlen);
	res = TEE_MACComputeFinal(op, &R, sizeof(uint8_t), hmac_buf, &hmac_length);
	if (res != TEE_SUCCESS) {
		EMSG("Failed to compute HMAC, res=%x", res);
		goto free_op;
	}

	//Output data
	memcpy(uniqueID, hmac_buf, UNIQUE_ID_BUFFER_SIZE);
	*uniqueIDlen = UNIQUE_ID_BUFFER_SIZE;

free_op:
	TEE_FreeOperation(op);
exit:
	return res;
}

#ifdef CFG_ATTESTATION_PROVISIONING
TEE_Result TA_SetAttestationKey(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	size_t  in_size = 0;
	keymaster_blob_t input = EMPTY_BLOB;	/* IN */
	keymaster_algorithm_t algorithm = 0;	/* IN */
	keymaster_error_t res = KM_ERROR_OK;
	TEE_Result result = TEE_SUCCESS;

	in = (uint8_t *)params[0].memref.buffer;
	in_size = (size_t)params[0].memref.size;
	in_end = in + in_size;

	DMSG("%s %d", __func__, __LINE__);
	if (in_size == 0)
		return TEE_SUCCESS;
	if (TA_is_out_of_bounds(in, in_end, sizeof(algorithm))) {
		EMSG("Out of input array bounds on deserialization");
		return TEE_ERROR_OVERFLOW;
	}
	TEE_MemMove(&algorithm, in, sizeof(algorithm));
	in += sizeof(algorithm);
	TA_deserialize_blob_akms(in, in_end, &input, false, &res, true);
	if (res != KM_ERROR_OK) {
		EMSG("Error parsing inputs!");
		result = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

    switch (algorithm) {
    case KM_ALGORITHM_RSA:
		result = TA_set_rsa_attest_key(input);
		if (result != TEE_SUCCESS) {
			EMSG("Something wrong with root RSA key, res=%x", result);
			res = KM_ERROR_UNKNOWN_ERROR;
			break;
		}
        break;
    case KM_ALGORITHM_EC:
		result = TA_set_ec_attest_key(input);
		if (result != TEE_SUCCESS) {
			EMSG("Something wrong with root EC key, res=%x", result);
			res = KM_ERROR_UNKNOWN_ERROR;
			break;
		}
        break;
    default:
		EMSG("Unsupported algorithm! Only RSA and EC are supported.");
		res = KM_ERROR_UNSUPPORTED_ALGORITHM;
		result = TEE_ERROR_BAD_PARAMETERS;
	break;
    }

out:
	return result;
}

TEE_Result TA_AppendAttestationCertKey(TEE_Param params[TEE_NUM_PARAMS])
{
	uint8_t *in = NULL;
	uint8_t *in_end = NULL;
	size_t  in_size = 0;
	keymaster_blob_t input = EMPTY_BLOB;	/* IN */
	keymaster_algorithm_t algorithm = 0;	/* IN */
	keymaster_error_t res = KM_ERROR_OK;
	TEE_Result result = TEE_SUCCESS;

	in = (uint8_t *)params[0].memref.buffer;
	in_size = (size_t)params[0].memref.size;
	in_end = in + in_size;

	DMSG("%s %d", __func__, __LINE__);
	if (in_size == 0)
		return TEE_SUCCESS;
	if (TA_is_out_of_bounds(in, in_end, sizeof(algorithm))) {
		EMSG("Out of input array bounds on deserialization");
		return TEE_ERROR_OVERFLOW;
	}
	TEE_MemMove(&algorithm, in, sizeof(algorithm));
	in += sizeof(algorithm);
	TA_deserialize_blob_akms(in, in_end, &input, false, &res, true);
	if (res != KM_ERROR_OK) {
		EMSG("Error parsing inputs!");
		result = TEE_ERROR_BAD_FORMAT;
		goto out;
	}

    switch (algorithm) {
    case KM_ALGORITHM_RSA:
		result = TA_append_root_rsa_attest_cert(input);
		if (result != TEE_SUCCESS) {
			EMSG("Something wrong with root RSA certificate, res=%x", result);
			res = KM_ERROR_UNKNOWN_ERROR;
		}
        break;
    case KM_ALGORITHM_EC:
		result = TA_append_root_ec_attest_cert(input);
		if (result != TEE_SUCCESS) {
			EMSG("Something wrong with root EC certificate, res=%x", result);
			res = KM_ERROR_UNKNOWN_ERROR;
		}
        break;
    default:
		EMSG("Unsupported algorithm! Only RSA and EC are supported.");
		res = KM_ERROR_UNSUPPORTED_ALGORITHM;
		result = TEE_ERROR_BAD_PARAMETERS;
	break;
    }

out:
	return result;
}
#endif
