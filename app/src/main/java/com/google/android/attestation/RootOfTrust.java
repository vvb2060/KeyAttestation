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

import static com.google.android.attestation.Constants.KM_VERIFIED_BOOT_STATE_FAILED;
import static com.google.android.attestation.Constants.KM_VERIFIED_BOOT_STATE_SELF_SIGNED;
import static com.google.android.attestation.Constants.KM_VERIFIED_BOOT_STATE_UNVERIFIED;
import static com.google.android.attestation.Constants.KM_VERIFIED_BOOT_STATE_VERIFIED;
import static com.google.android.attestation.Constants.ROOT_OF_TRUST_DEVICE_LOCKED_INDEX;
import static com.google.android.attestation.Constants.ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX;
import static com.google.android.attestation.Constants.ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX;
import static com.google.android.attestation.Constants.ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;

/** This collection of values defines key information about the device's status. */
public class RootOfTrust {

  public final byte[] verifiedBootKey;
  public final boolean deviceLocked;
  public final VerifiedBootState verifiedBootState;
  public final byte[] verifiedBootHash;

  private RootOfTrust(ASN1Sequence rootOfTrust, int attestationVersion) {
    this.verifiedBootKey =
        ((ASN1OctetString) rootOfTrust.getObjectAt(ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX))
            .getOctets();
    this.deviceLocked =
        ASN1Parsing.getBooleanFromAsn1(rootOfTrust.getObjectAt(ROOT_OF_TRUST_DEVICE_LOCKED_INDEX));
    this.verifiedBootState =
        verifiedBootStateToEnum(
            ASN1Parsing.getIntegerFromAsn1(
                rootOfTrust.getObjectAt(ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX)));
    if (attestationVersion >= 3) {
      this.verifiedBootHash =
          ((ASN1OctetString) rootOfTrust.getObjectAt(ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX))
              .getOctets();
    } else {
      this.verifiedBootHash = null;
    }
  }

  static RootOfTrust createRootOfTrust(ASN1Sequence rootOfTrust, int attestationVersion) {
    if (rootOfTrust == null) {
      return null;
    }
    return new RootOfTrust(rootOfTrust, attestationVersion);
  }

  private static VerifiedBootState verifiedBootStateToEnum(int securityLevel) {
    switch (securityLevel) {
      case KM_VERIFIED_BOOT_STATE_VERIFIED:
        return VerifiedBootState.VERIFIED;
      case KM_VERIFIED_BOOT_STATE_SELF_SIGNED:
        return VerifiedBootState.SELF_SIGNED;
      case KM_VERIFIED_BOOT_STATE_UNVERIFIED:
        return VerifiedBootState.UNVERIFIED;
      case KM_VERIFIED_BOOT_STATE_FAILED:
        return VerifiedBootState.FAILED;
      default:
        throw new IllegalArgumentException("Invalid verified boot state.");
    }
  }

  /**
   * This provides the device's current boot state, which represents the level of protection
   * provided to the user and to apps after the device finishes booting.
   */
  public enum VerifiedBootState {
    VERIFIED,
    SELF_SIGNED,
    UNVERIFIED,
    FAILED
  }
}
