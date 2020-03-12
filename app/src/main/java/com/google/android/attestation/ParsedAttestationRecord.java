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

import static com.google.android.attestation.Constants.ATTESTATION_CHALLENGE_INDEX;
import static com.google.android.attestation.Constants.ATTESTATION_SECURITY_LEVEL_INDEX;
import static com.google.android.attestation.Constants.ATTESTATION_VERSION_INDEX;
import static com.google.android.attestation.Constants.KEYMASTER_SECURITY_LEVEL_INDEX;
import static com.google.android.attestation.Constants.KEYMASTER_VERSION_INDEX;
import static com.google.android.attestation.Constants.KEY_DESCRIPTION_OID;
import static com.google.android.attestation.Constants.KM_SECURITY_LEVEL_SOFTWARE;
import static com.google.android.attestation.Constants.KM_SECURITY_LEVEL_STRONG_BOX;
import static com.google.android.attestation.Constants.KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT;
import static com.google.android.attestation.Constants.SW_ENFORCED_INDEX;
import static com.google.android.attestation.Constants.TEE_ENFORCED_INDEX;
import static com.google.android.attestation.Constants.UNIQUE_ID_INDEX;

import java.io.IOException;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;

/** Java representation of Key Attestation extension data. */
public class ParsedAttestationRecord {

  public final int attestationVersion;
  public final SecurityLevel attestationSecurityLevel;
  public final int keymasterVersion;
  public final SecurityLevel keymasterSecurityLevel;
  public final byte[] attestationChallenge;
  public final byte[] uniqueId;
  public final AuthorizationList softwareEnforced;
  public final AuthorizationList teeEnforced;

  private ParsedAttestationRecord(ASN1Sequence extensionData) {
    this.attestationVersion =
        ASN1Parsing.getIntegerFromAsn1(extensionData.getObjectAt(ATTESTATION_VERSION_INDEX));
    this.attestationSecurityLevel =
        securityLevelToEnum(
            ASN1Parsing.getIntegerFromAsn1(
                extensionData.getObjectAt(ATTESTATION_SECURITY_LEVEL_INDEX)));
    this.keymasterVersion =
        ASN1Parsing.getIntegerFromAsn1(extensionData.getObjectAt(KEYMASTER_VERSION_INDEX));
    this.keymasterSecurityLevel =
        securityLevelToEnum(
            ASN1Parsing.getIntegerFromAsn1(
                extensionData.getObjectAt(KEYMASTER_SECURITY_LEVEL_INDEX)));
    this.attestationChallenge =
        ((ASN1OctetString) extensionData.getObjectAt(ATTESTATION_CHALLENGE_INDEX)).getOctets();
    this.uniqueId = ((ASN1OctetString) extensionData.getObjectAt(UNIQUE_ID_INDEX)).getOctets();
    this.softwareEnforced =
        AuthorizationList.createAuthorizationList(
            ((ASN1Sequence) extensionData.getObjectAt(SW_ENFORCED_INDEX)).toArray(),
            attestationVersion);
    this.teeEnforced =
        AuthorizationList.createAuthorizationList(
            ((ASN1Sequence) extensionData.getObjectAt(TEE_ENFORCED_INDEX)).toArray(),
            attestationVersion);
  }

  public static ParsedAttestationRecord createParsedAttestationRecord(X509Certificate cert)
      throws IOException {
    ASN1Sequence extensionData = extractAttestationSequence(cert);
    return new ParsedAttestationRecord(extensionData);
  }

  private static SecurityLevel securityLevelToEnum(int securityLevel) {
    switch (securityLevel) {
      case KM_SECURITY_LEVEL_SOFTWARE:
        return SecurityLevel.SOFTWARE;
      case KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
        return SecurityLevel.TRUSTED_ENVIRONMENT;
      case KM_SECURITY_LEVEL_STRONG_BOX:
        return SecurityLevel.STRONG_BOX;
      default:
        throw new IllegalArgumentException("Invalid security level.");
    }
  }

  private static ASN1Sequence extractAttestationSequence(X509Certificate attestationCert)
      throws IOException {
    byte[] attestationExtensionBytes = attestationCert.getExtensionValue(KEY_DESCRIPTION_OID);
    if (attestationExtensionBytes == null || attestationExtensionBytes.length == 0) {
      throw new IllegalArgumentException("The device does not support key attestation.");
    }

    ASN1Sequence decodedSequence;
    try (ASN1InputStream asn1InputStream = new ASN1InputStream(attestationExtensionBytes)) {
      // The extension contains one object, a sequence, in the
      // Distinguished Encoding Rules (DER)-encoded form. Get the DER
      // bytes.
      byte[] derSequenceBytes = ((ASN1OctetString) asn1InputStream.readObject()).getOctets();
      // Decode the bytes as an ASN1 sequence object.
      try (ASN1InputStream seqInputStream = new ASN1InputStream(derSequenceBytes)) {
        decodedSequence = (ASN1Sequence) seqInputStream.readObject();
      }
    }
    return decodedSequence;
  }

  /**
   * This indicates the extent to which a software feature, such as a key pair, is protected based
   * on its location within the device.
   */
  public enum SecurityLevel {
    SOFTWARE,
    TRUSTED_ENVIRONMENT,
    STRONG_BOX
  }
}
