/*
 * Copyright (C) 2021 The Android Open Source Project
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

package android.hardware.security.keymint;

/**
 * DeviceInfo contains information about the device that's signed by the
 * IRemotelyProvisionedComponent HAL. These values are intended to be checked by the server to
 * verify that the certificate signing request crafted by an IRemotelyProvisionedComponent HAL
 * instance is coming from the expected device based on values initially uploaded during device
 * manufacture in the factory.
 * @hide
 */
parcelable DeviceInfo {
    /**
     * DeviceInfo is a CBOR Map structure described by the following CDDL. DeviceInfo must be
     * ordered according to the Length-First Map Key Ordering specified in RFC 8949,
     * Section 4.2.3. Please note that the ordering presented here groups similar entries
     * semantically, and not in the correct order per RFC 8949, Section 4.2.3.
     *
     * The DeviceInfo has changed across versions 1, 2, and 3 of the HAL. All versions of the
     * DeviceInfo CDDL are described in the DeviceInfoV*.cddl files. Please refer to the CDDL
     * structure version that corresponds to the HAL version you are working with.
     *
     */
    byte[] deviceInfo;
}
