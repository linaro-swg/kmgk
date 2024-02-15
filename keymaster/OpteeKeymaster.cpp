/*
 * Copyright 2018 The Android Open Source Project
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

#define LOG_TAG "optee_keymaster_hal"
#include <android-base/logging.h>

#include <keymaster/android_keymaster_messages.h>
#include <keymaster/keymaster_configuration.h>
#include <optee_keymaster/OpteeKeymaster.h>
#include <optee_keymaster/ipc/optee_keymaster_ipc.h>

namespace keymaster {

int OpteeKeymaster::Initialize(KmVersion version) {
    int err;

    LOG(INFO) << "Initializing OpteeKeymaster as KmVersion: " << (int)version;

    err = optee_keymaster_connect();
    if (err) {
        LOG(ERROR) << "Failed to connect to optee keymaster (1st try)" << err;
        return err;
    }

    // Try GetVersion2 first.
    GetVersion2Request versionReq;
    versionReq.max_message_version = MessageVersion(version);
    GetVersion2Response versionRsp = GetVersion2(versionReq);
    if (versionRsp.error != KM_ERROR_OK) {
        LOG(WARNING) << "TA appears not to support GetVersion2, falling back (err = "
                     << versionRsp.error << ")";

        err = optee_keymaster_connect();
        if (err) {
            LOG(FATAL) << "Failed to connect to optee keymaster (2nd try) " << err;
            return err;
        }

        GetVersionRequest versionReq;
        GetVersionResponse versionRsp;
        GetVersion(versionReq, &versionRsp);
        if (versionRsp.error != KM_ERROR_OK) {
            LOG(FATAL) << "Failed to get TA version " << versionRsp.error;
            return -1;
        } else {
            keymaster_error_t error;
            message_version_ = NegotiateMessageVersion(versionRsp, &error);
            if (error != KM_ERROR_OK) {
                LOG(FATAL) << "Failed to negotiate message version " << error;
                return -1;
            }
        }
    } else {
        message_version_ = NegotiateMessageVersion(versionReq, versionRsp);
    }

    ConfigureRequest req(message_version());
    req.os_version = GetOsVersion();
    req.os_patchlevel = GetOsPatchlevel();

    ConfigureResponse rsp(message_version());
    Configure(req, &rsp);

    if (rsp.error != KM_ERROR_OK) {
        LOG(FATAL) << "Failed to configure keymaster " << rsp.error;
        return -1;
    }

    // Set the vendor patchlevel to value retrieved from system property (which
    // requires SELinux permission).
    ConfigureVendorPatchlevelRequest vendor_req(message_version());
    vendor_req.vendor_patchlevel = GetVendorPatchlevel();
    ConfigureVendorPatchlevelResponse vendor_rsp = ConfigureVendorPatchlevel(vendor_req);
    if (vendor_rsp.error != KM_ERROR_OK) {
        LOG(ERROR) << "Failed to configure keymaster vendor patchlevel: " << vendor_rsp.error;
        // Don't fail if this message isn't understood.
    }

    return 0;
}

OpteeKeymaster::OpteeKeymaster() {}

OpteeKeymaster::~OpteeKeymaster() {
    optee_keymaster_disconnect();
}

static void ForwardCommand(enum keymaster_command command, const KeymasterMessage& req,
                           KeymasterResponse* rsp) {
    keymaster_error_t err;
    err = optee_keymaster_send(command, req, rsp);
    if (err != KM_ERROR_OK) {
        LOG(ERROR) << "Cmd " << command << " returned error: " << err;
        rsp->error = err;
    }
}

void OpteeKeymaster::GetVersion(const GetVersionRequest& request, GetVersionResponse* response) {
    ForwardCommand(KM_GET_VERSION, request, response);
}

void OpteeKeymaster::SupportedAlgorithms(const SupportedAlgorithmsRequest& request,
                                          SupportedAlgorithmsResponse* response) {
    ForwardCommand(KM_GET_SUPPORTED_ALGORITHMS, request, response);
}

void OpteeKeymaster::SupportedBlockModes(const SupportedBlockModesRequest& request,
                                          SupportedBlockModesResponse* response) {
    ForwardCommand(KM_GET_SUPPORTED_BLOCK_MODES, request, response);
}

void OpteeKeymaster::SupportedPaddingModes(const SupportedPaddingModesRequest& request,
                                            SupportedPaddingModesResponse* response) {
    ForwardCommand(KM_GET_SUPPORTED_PADDING_MODES, request, response);
}

void OpteeKeymaster::SupportedDigests(const SupportedDigestsRequest& request,
                                       SupportedDigestsResponse* response) {
    ForwardCommand(KM_GET_SUPPORTED_DIGESTS, request, response);
}

void OpteeKeymaster::SupportedImportFormats(const SupportedImportFormatsRequest& request,
                                             SupportedImportFormatsResponse* response) {
    ForwardCommand(KM_GET_SUPPORTED_IMPORT_FORMATS, request, response);
}

void OpteeKeymaster::SupportedExportFormats(const SupportedExportFormatsRequest& request,
                                             SupportedExportFormatsResponse* response) {
    ForwardCommand(KM_GET_SUPPORTED_EXPORT_FORMATS, request, response);
}

void OpteeKeymaster::AddRngEntropy(const AddEntropyRequest& request,
                                    AddEntropyResponse* response) {
    ForwardCommand(KM_ADD_RNG_ENTROPY, request, response);
}

void OpteeKeymaster::Configure(const ConfigureRequest& request, ConfigureResponse* response) {
    ForwardCommand(KM_CONFIGURE, request, response);
}

void OpteeKeymaster::GenerateKey(const GenerateKeyRequest& request,
                                  GenerateKeyResponse* response) {
    if (message_version_ < 4) {
        // Pre-KeyMint we need to add TAG_CREATION_DATETIME if not provided by the caller.
        GenerateKeyRequest datedRequest(request.message_version);
        datedRequest.key_description = request.key_description;

        if (!request.key_description.Contains(TAG_CREATION_DATETIME)) {
            datedRequest.key_description.push_back(TAG_CREATION_DATETIME, java_time(time(NULL)));
        }

        ForwardCommand(KM_GENERATE_KEY, datedRequest, response);
    } else {
        ForwardCommand(KM_GENERATE_KEY, request, response);
    }
}

void OpteeKeymaster::GenerateRkpKey(const GenerateRkpKeyRequest& request,
                                     GenerateRkpKeyResponse* response) {
    ForwardCommand(KM_GENERATE_RKP_KEY, request, response);
}

void OpteeKeymaster::GenerateCsr(const GenerateCsrRequest& request,
                                  GenerateCsrResponse* response) {
    ForwardCommand(KM_GENERATE_CSR, request, response);
}

void OpteeKeymaster::GenerateCsrV2(const GenerateCsrV2Request& request,
                                    GenerateCsrV2Response* response) {
    ForwardCommand(KM_GENERATE_CSR_V2, request, response);
}

void OpteeKeymaster::GetKeyCharacteristics(const GetKeyCharacteristicsRequest& request,
                                            GetKeyCharacteristicsResponse* response) {
    ForwardCommand(KM_GET_KEY_CHARACTERISTICS, request, response);
}

void OpteeKeymaster::ImportKey(const ImportKeyRequest& request, ImportKeyResponse* response) {
    ForwardCommand(KM_IMPORT_KEY, request, response);
}

void OpteeKeymaster::ImportWrappedKey(const ImportWrappedKeyRequest& request,
                                       ImportWrappedKeyResponse* response) {
    ForwardCommand(KM_IMPORT_WRAPPED_KEY, request, response);
}

void OpteeKeymaster::ExportKey(const ExportKeyRequest& request, ExportKeyResponse* response) {
    ForwardCommand(KM_EXPORT_KEY, request, response);
}

void OpteeKeymaster::AttestKey(const AttestKeyRequest& request, AttestKeyResponse* response) {
    ForwardCommand(KM_ATTEST_KEY, request, response);
}

void OpteeKeymaster::UpgradeKey(const UpgradeKeyRequest& request, UpgradeKeyResponse* response) {
    ForwardCommand(KM_UPGRADE_KEY, request, response);
}

void OpteeKeymaster::DeleteKey(const DeleteKeyRequest& request, DeleteKeyResponse* response) {
    ForwardCommand(KM_DELETE_KEY, request, response);
}

void OpteeKeymaster::DeleteAllKeys(const DeleteAllKeysRequest& request,
                                    DeleteAllKeysResponse* response) {
    ForwardCommand(KM_DELETE_ALL_KEYS, request, response);
}

void OpteeKeymaster::BeginOperation(const BeginOperationRequest& request,
                                     BeginOperationResponse* response) {
    ForwardCommand(KM_BEGIN_OPERATION, request, response);
}

void OpteeKeymaster::UpdateOperation(const UpdateOperationRequest& request,
                                      UpdateOperationResponse* response) {
    ForwardCommand(KM_UPDATE_OPERATION, request, response);
}

void OpteeKeymaster::FinishOperation(const FinishOperationRequest& request,
                                      FinishOperationResponse* response) {
    ForwardCommand(KM_FINISH_OPERATION, request, response);
}

void OpteeKeymaster::AbortOperation(const AbortOperationRequest& request,
                                     AbortOperationResponse* response) {
    ForwardCommand(KM_ABORT_OPERATION, request, response);
}

GetHmacSharingParametersResponse OpteeKeymaster::GetHmacSharingParameters() {
    GetHmacSharingParametersRequest request(message_version());
    GetHmacSharingParametersResponse response(message_version());
    ForwardCommand(KM_GET_HMAC_SHARING_PARAMETERS, request, &response);
    return response;
}

ComputeSharedHmacResponse OpteeKeymaster::ComputeSharedHmac(
        const ComputeSharedHmacRequest& request) {
    ComputeSharedHmacResponse response(message_version());
    ForwardCommand(KM_COMPUTE_SHARED_HMAC, request, &response);
    return response;
}

VerifyAuthorizationResponse OpteeKeymaster::VerifyAuthorization(
        const VerifyAuthorizationRequest& request) {
    VerifyAuthorizationResponse response(message_version());
    ForwardCommand(KM_VERIFY_AUTHORIZATION, request, &response);
    return response;
}

GetVersion2Response OpteeKeymaster::GetVersion2(const GetVersion2Request& request) {
    GetVersion2Response response(message_version());
    ForwardCommand(KM_GET_VERSION_2, request, &response);
    return response;
}

EarlyBootEndedResponse OpteeKeymaster::EarlyBootEnded() {
    EarlyBootEndedResponse response(message_version());
    ForwardCommand(KM_EARLY_BOOT_ENDED, EarlyBootEndedRequest(message_version()), &response);
    return response;
}

DeviceLockedResponse OpteeKeymaster::DeviceLocked(const DeviceLockedRequest& request) {
    DeviceLockedResponse response(message_version());
    ForwardCommand(KM_DEVICE_LOCKED, request, &response);
    return response;
}

ConfigureVendorPatchlevelResponse OpteeKeymaster::ConfigureVendorPatchlevel(
        const ConfigureVendorPatchlevelRequest& request) {
    ConfigureVendorPatchlevelResponse response(message_version());
    ForwardCommand(KM_CONFIGURE_VENDOR_PATCHLEVEL, request, &response);
    return response;
}

GetRootOfTrustResponse OpteeKeymaster::GetRootOfTrust(const GetRootOfTrustRequest& request) {
    GetRootOfTrustResponse response(message_version());
    ForwardCommand(KM_GET_ROOT_OF_TRUST, request, &response);
    return response;
}

GetHwInfoResponse OpteeKeymaster::GetHwInfo() {
    GetHwInfoResponse response(message_version());
    ForwardCommand(KM_GET_HW_INFO, GetHwInfoRequest(message_version()), &response);
    return response;
}

}  // namespace keymaster
