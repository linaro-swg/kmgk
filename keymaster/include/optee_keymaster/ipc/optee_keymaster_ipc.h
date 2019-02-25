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

__BEGIN_DECLS

bool optee_keystore_connect(void);

keymaster_error_t optee_keystore_call(uint32_t cmd, void* in, uint32_t in_size,
                        void* out, uint32_t out_size);

void optee_keystore_disconnect(void);

const char* print_error_message(uint32_t error);

__END_DECLS
#endif /* OPTEE_KEYMASTER_IPC_H */
