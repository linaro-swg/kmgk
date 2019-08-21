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
 #ifndef OPTEE_KEYMASTER_IPC_H
 #define OPTEE_KEYMASTER_IPC_H

#include <keymaster/android_keymaster_messages.h>
#include <optee_keymaster/ipc/keymaster_ipc.h>
__BEGIN_DECLS

#define TA_KEYMASTER_UUID { 0xdba51a17, 0x0563, 0x11e7, \
		{ 0x93, 0xb1, 0x6f, 0xa7, 0xb0, 0x07, 0x1a, 0x51} }

const uint32_t OPTEE_KEYMASTER_RECV_BUF_SIZE = 2 * PAGE_SIZE;
const uint32_t OPTEE_KEYMASTER_SEND_BUF_SIZE = 2 * PAGE_SIZE;

int optee_keymaster_initialize(void);
int optee_keymaster_connect(void);

keymaster_error_t optee_keymaster_call(uint32_t cmd, const keymaster::Serializable& req,
                        keymaster::KeymasterResponse* rsp);

void optee_keymaster_disconnect(void);
void optee_keymaster_finalize(void);

const char* print_error_message(uint32_t error);

__END_DECLS
#endif /* OPTEE_KEYMASTER_IPC_H */
