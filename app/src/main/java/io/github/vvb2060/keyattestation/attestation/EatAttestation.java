/*
 * Copyright (C) 2020 The Android Open Source Project
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

package io.github.vvb2060.keyattestation.attestation;

import android.util.Log;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.Number;
import co.nstant.in.cbor.model.UnicodeString;

import org.bouncycastle.asn1.ASN1Encodable;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

public class EatAttestation extends Attestation {
    static final String TAG = "EatAttestation";
    final Map extension;
    final RootOfTrust rootOfTrust;

    /**
     * Constructs an {@code EatAttestation} object from the provided {@link X509Certificate},
     * extracting the attestation data from the attestation extension.
     *
     * @throws CertificateParsingException if the certificate does not contain a properly-formatted
     *     attestation extension.
     */
    public EatAttestation(X509Certificate x509Cert)
            throws CertificateParsingException, CborException {
        super(x509Cert);
        extension = getEatExtension(x509Cert);

        RootOfTrust.Builder rootOfTrustBuilder = new RootOfTrust.Builder();
        List<Boolean> bootState = null;
        boolean officialBuild = false;

        for (DataItem key : extension.getKeys()) {
            int keyInt = ((Number) key).getValue().intValue();
            switch (keyInt) {
                default:
                    throw new CertificateParsingException(
                            "Unknown EAT tag: " + key + "\n in EAT extension:\n" + this);

                case EatClaim.ATTESTATION_VERSION:
                    attestationVersion = CborUtils.getInt(extension, key);
                    break;
                case EatClaim.KEYMASTER_VERSION:
                    keymasterVersion = CborUtils.getInt(extension, key);
                    break;
                case EatClaim.SECURITY_LEVEL:
                    keymasterSecurityLevel =
                            eatSecurityLevelToKeymintSecurityLevel(
                                    CborUtils.getInt(extension, key));
                    break;
                case EatClaim.SUBMODS:
                    Map submods = (Map) extension.get(key);
                    softwareEnforced =
                            new AuthorizationList(
                                    (Map) submods.get(new UnicodeString(EatClaim.SUBMOD_SOFTWARE)));
                    teeEnforced =
                            new AuthorizationList(
                                    (Map) submods.get(new UnicodeString(EatClaim.SUBMOD_TEE)));
                    break;
                case EatClaim.VERIFIED_BOOT_KEY:
                    rootOfTrustBuilder.setVerifiedBootKey(CborUtils.getBytes(extension, key));
                    break;
                case EatClaim.DEVICE_LOCKED:
                    rootOfTrustBuilder.setDeviceLocked(CborUtils.getBoolean(extension, key));
                    break;
                case EatClaim.BOOT_STATE:
                    bootState = CborUtils.getBooleanList(extension, key);
                    break;
                case EatClaim.OFFICIAL_BUILD:
                    officialBuild = CborUtils.getBoolean(extension, key);
                    break;
                case EatClaim.NONCE:
                    attestationChallenge = CborUtils.getBytes(extension, key);
                    break;
                case EatClaim.CTI:
                    Log.i(TAG, "Got CTI claim: " + Arrays.toString(CborUtils.getBytes(extension, key)));
                    uniqueId = CborUtils.getBytes(extension, key);
                    break;
                case EatClaim.VERIFIED_BOOT_HASH:
                    rootOfTrustBuilder.setVerifiedBootHash(CborUtils.getBytes(extension, key));
                    break;
            }
        }

        if (bootState != null) {
            rootOfTrustBuilder.setVerifiedBootState(
                    eatBootStateTypeToVerifiedBootState(bootState, officialBuild));
        }
        rootOfTrust = rootOfTrustBuilder.build();
    }

    /** Find the submod containing the key information, and return its security level. */
    public int getAttestationSecurityLevel() {
        if (teeEnforced != null && teeEnforced.getAlgorithm() != null) {
            return teeEnforced.getSecurityLevel();
        } else if (softwareEnforced != null && softwareEnforced.getAlgorithm() != null) {
            return softwareEnforced.getSecurityLevel();
        } else {
            return -1;
        }
    }

    public RootOfTrust getRootOfTrust() {
        return rootOfTrust;
    }

    public String toString() {
        return super.toString() + "\nEncoded CBOR: " + extension;
    }

    Map getEatExtension(X509Certificate x509Cert)
            throws CertificateParsingException, CborException {
        byte[] attestationExtensionBytes = x509Cert.getExtensionValue(Attestation.EAT_OID);
        if (attestationExtensionBytes == null || attestationExtensionBytes.length == 0) {
            throw new CertificateParsingException("Did not find extension with OID " + EAT_OID);
        }
        ASN1Encodable asn1 = Asn1Utils.getAsn1EncodableFromBytes(attestationExtensionBytes);
        byte[] cborBytes = Asn1Utils.getByteArrayFromAsn1(asn1);
        return (Map) CborUtils.decodeCbor(cborBytes);
    }

    static int eatSecurityLevelToKeymintSecurityLevel(int eatSecurityLevel) {
        switch (eatSecurityLevel) {
            case EatClaim.SECURITY_LEVEL_UNRESTRICTED:
                return Attestation.KM_SECURITY_LEVEL_SOFTWARE;
            case EatClaim.SECURITY_LEVEL_SECURE_RESTRICTED:
                return Attestation.KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT;
            case EatClaim.SECURITY_LEVEL_HARDWARE:
                return Attestation.KM_SECURITY_LEVEL_STRONG_BOX;
            default:
                throw new RuntimeException("Invalid EAT security level: " + eatSecurityLevel);
        }
    }

    static int eatBootStateTypeToVerifiedBootState(List<Boolean> bootState, Boolean officialBuild) {
        if (bootState.size() != 5) {
            throw new RuntimeException("Boot state map has unexpected size: " + bootState.size());
        }
        if (bootState.get(4)) {
            throw new RuntimeException("debug-permanent-disable must never be true: " + bootState);
        }
        boolean verifiedOrSelfSigned = bootState.get(0);
        if (verifiedOrSelfSigned != bootState.get(1)
                && verifiedOrSelfSigned != bootState.get(2)
                && verifiedOrSelfSigned != bootState.get(3)) {
            throw new RuntimeException("Unexpected boot state: " + bootState);
        }

        if (officialBuild) {
            if (!verifiedOrSelfSigned) {
                throw new AssertionError("Non-verified official build");
            }
            return RootOfTrust.KM_VERIFIED_BOOT_VERIFIED;
        } else {
            return verifiedOrSelfSigned
                    ? RootOfTrust.KM_VERIFIED_BOOT_SELF_SIGNED
                    : RootOfTrust.KM_VERIFIED_BOOT_UNVERIFIED;
        }
    }
}
