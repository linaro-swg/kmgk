#
# Copyright (C) 2017 GlobalLogic
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Include only for HiKey ones in space separated list
# E.g. hikey hikey960 hikey970
# Temporarily disable so that this can be built on multiple platforms
#ifneq (,$(filter $(TARGET_PRODUCT), hikey))
LOCAL_PATH:= $(call my-dir)

################################################################################
# Build keymaster HAL TA                                                       #
################################################################################
include $(LOCAL_PATH)/ta/Android.mk

#endif # Include only for HiKey ones.
