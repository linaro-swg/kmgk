/*
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

#include <log/log.h>
#include <keymaster/android_keymaster_messages.h>
#include <keymaster/keymaster_configuration.h>
#include <optee_keymaster/optee_keymaster.h>
#include <optee_keymaster/ipc/optee_keymaster_ipc.h>

#undef LOG_TAG
#define LOG_TAG "OpteeKeymaster_cpp"

namespace keymaster {

int OpteeKeymaster::Initialize() {
    int err;

    err = optee_keymaster_connect();
    if (err) {
        ALOGE("Failed to connect to optee keymaster %d", err);
        return err;
    }

    ConfigureRequest req;
    req.os_version = GetOsVersion();
    req.os_patchlevel = GetOsPatchlevel();

    ConfigureResponse rsp;
    Configure(req, &rsp);

    if (rsp.error != KM_ERROR_OK) {
        ALOGE("Failed to configure keymaster %d", rsp.error);
        return -1;
    }

    return 0;
}

OpteeKeymaster::OpteeKeymaster() {}

OpteeKeymaster::~OpteeKeymaster() {
    optee_keymaster_disconnect();
}

static void ForwardCommand(enum keymaster_command command, const Serializable& req,
                           KeymasterResponse* rsp) {
    keymaster_error_t err;
    err = optee_keymaster_call(command, req, rsp);
    if (err != KM_ERROR_OK) {
        ALOGE("Failed to send cmd %d err: %d", command, err);
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
    GenerateKeyRequest datedRequest(request.message_version);
    datedRequest.key_description = request.key_description;

    if (!request.key_description.Contains(TAG_CREATION_DATETIME)) {
        datedRequest.key_description.push_back(TAG_CREATION_DATETIME, java_time(time(NULL)));
    }

    ForwardCommand(KM_GENERATE_KEY, datedRequest, response);
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

/* Methods for Keymaster 4.0 functionality -- not yet implemented */
GetHmacSharingParametersResponse OpteeKeymaster::GetHmacSharingParameters() {
    GetHmacSharingParametersResponse response;
    response.error = KM_ERROR_UNIMPLEMENTED;
    return response;
}

ComputeSharedHmacResponse OpteeKeymaster::ComputeSharedHmac(
        const ComputeSharedHmacRequest& /* request */) {
    ComputeSharedHmacResponse response;
    response.error = KM_ERROR_UNIMPLEMENTED;
    return response;
}

VerifyAuthorizationResponse OpteeKeymaster::VerifyAuthorization(
        const VerifyAuthorizationRequest& /* request */) {
    VerifyAuthorizationResponse response;
    response.error = KM_ERROR_UNIMPLEMENTED;
    return response;
}

}  // namespace keymaster
