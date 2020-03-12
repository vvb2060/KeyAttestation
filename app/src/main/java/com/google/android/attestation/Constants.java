/* Copyright 2019, The Android Open Source Project, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.android.attestation;

/** Key Attestation constants */
public class Constants {

  // The Google root certificate that must have been used to sign the root
  // certificate in a real attestation certificate chain from a compliant
  // device.
  // (Note, the sample chain used here is not signed with this certificate.)
  public static final String GOOGLE_ROOT_CERTIFICATE =
      "-----BEGIN CERTIFICATE-----\n"
          + "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\n"
          + "-----END CERTIFICATE-----";
  static final String KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17";
  static final int ATTESTATION_VERSION_INDEX = 0;
  static final int ATTESTATION_SECURITY_LEVEL_INDEX = 1;
  static final int KEYMASTER_VERSION_INDEX = 2;
  static final int KEYMASTER_SECURITY_LEVEL_INDEX = 3;
  static final int ATTESTATION_CHALLENGE_INDEX = 4;
  static final int UNIQUE_ID_INDEX = 5;
  static final int SW_ENFORCED_INDEX = 6;
  static final int TEE_ENFORCED_INDEX = 7;
  // Authorization list tags. The list is in this AOSP file:
  // hardware/libhardware/include/hardware/keymaster_defs.h
  static final int KM_TAG_PURPOSE = 1;
  static final int KM_TAG_ALGORITHM = 2;
  static final int KM_TAG_KEY_SIZE = 3;
  static final int KM_TAG_DIGEST = 5;
  static final int KM_TAG_PADDING = 6;
  static final int KM_TAG_EC_CURVE = 10;
  static final int KM_TAG_RSA_PUBLIC_EXPONENT = 200;
  static final int KM_TAG_ROLLBACK_RESISTANCE = 303;
  static final int KM_TAG_ACTIVE_DATE_TIME = 400;
  static final int KM_TAG_ORIGINATION_EXPIRE_DATE_TIME = 401;
  static final int KM_TAG_USAGE_EXPIRE_DATE_TIME = 402;
  static final int KM_TAG_NO_AUTH_REQUIRED = 503;
  static final int KM_TAG_USER_AUTH_TYPE = 504;
  static final int KM_TAG_AUTH_TIMEOUT = 505;
  static final int KM_TAG_ALLOW_WHILE_ON_BODY = 506;
  static final int KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED = 507;
  static final int KM_TAG_TRUSTED_CONFIRMATION_REQUIRED = 508;
  static final int KM_TAG_UNLOCKED_DEVICE_REQUIRED = 509;
  static final int KM_TAG_ALL_APPLICATIONS = 600;
  static final int KM_TAG_APPLICATION_ID = 601;
  static final int KM_TAG_CREATION_DATE_TIME = 701;
  static final int KM_TAG_ORIGIN = 702;
  static final int KM_TAG_ROLLBACK_RESISTANT = 703;
  static final int KM_TAG_ROOT_OF_TRUST = 704;
  static final int KM_TAG_OS_VERSION = 705;
  static final int KM_TAG_OS_PATCH_LEVEL = 706;
  static final int KM_TAG_ATTESTATION_APPLICATION_ID = 709;
  static final int KM_TAG_ATTESTATION_ID_BRAND = 710;
  static final int KM_TAG_ATTESTATION_ID_DEVICE = 711;
  static final int KM_TAG_ATTESTATION_ID_PRODUCT = 712;
  static final int KM_TAG_ATTESTATION_ID_SERIAL = 713;
  static final int KM_TAG_ATTESTATION_ID_IMEI = 714;
  static final int KM_TAG_ATTESTATION_ID_MEID = 715;
  static final int KM_TAG_ATTESTATION_ID_MANUFACTURER = 716;
  static final int KM_TAG_ATTESTATION_ID_MODEL = 717;
  static final int KM_TAG_VENDOR_PATCH_LEVEL = 718;
  static final int KM_TAG_BOOT_PATCH_LEVEL = 719;
  static final int ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX = 0;
  static final int ROOT_OF_TRUST_DEVICE_LOCKED_INDEX = 1;
  static final int ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX = 2;
  static final int ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX = 3;
  static final int ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX = 0;
  static final int ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX = 1;
  static final int ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX = 0;
  static final int ATTESTATION_PACKAGE_INFO_VERSION_INDEX = 1;
  // Some security values. The complete list is in this AOSP file:
  // hardware/libhardware/include/hardware/keymaster_defs.h
  static final int KM_SECURITY_LEVEL_SOFTWARE = 0;
  static final int KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1;
  static final int KM_SECURITY_LEVEL_STRONG_BOX = 2;
  static final int KM_VERIFIED_BOOT_STATE_VERIFIED = 0;
  static final int KM_VERIFIED_BOOT_STATE_SELF_SIGNED = 1;
  static final int KM_VERIFIED_BOOT_STATE_UNVERIFIED = 2;
  static final int KM_VERIFIED_BOOT_STATE_FAILED = 3;
  // Unsigned max value of 32-bit integer, 2^32 - 1
  static final long UINT32_MAX = (((long) Integer.MAX_VALUE) << 1) + 1;
}
