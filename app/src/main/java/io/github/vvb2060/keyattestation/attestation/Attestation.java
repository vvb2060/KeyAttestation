/*
 * Copyright (C) 2016 The Android Open Source Project
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

import com.google.common.base.CharMatcher;
import com.google.common.collect.ImmutableSet;
import com.google.common.io.BaseEncoding;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Set;

import co.nstant.in.cbor.CborException;
import io.github.vvb2060.keyattestation.AppApplication;

/**
 * Parses an attestation certificate and provides an easy-to-use interface for examining the
 * contents.
 */
public abstract class Attestation {
    static final String KNOX_EXTENSION_OID = "1.3.6.1.4.1.236.11.3.23.7";
    static final String EAT_OID = "1.3.6.1.4.1.11129.2.1.25";
    static final String ASN1_OID = "1.3.6.1.4.1.11129.2.1.17";
    static final String KEY_USAGE_OID = "2.5.29.15"; // Standard key usage extension.
    static final String CRL_DP_OID = "2.5.29.31"; // Standard CRL Distribution Points extension.

    public static final int KM_SECURITY_LEVEL_SOFTWARE = 0;
    public static final int KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT = 1;
    public static final int KM_SECURITY_LEVEL_STRONG_BOX = 2;

    int attestationVersion;
    int keymasterVersion;
    int keymasterSecurityLevel;
    byte[] attestationChallenge;
    byte[] uniqueId;
    AuthorizationList softwareEnforced;
    AuthorizationList teeEnforced;
    Set<String> unexpectedExtensionOids;

    /**
     * Constructs an {@code Attestation} object from the provided {@link X509Certificate},
     * extracting the attestation data from the attestation extension.
     *
     * <p>This method ensures that at most one attestation extension is included in the certificate.
     *
     * @throws CertificateParsingException if the certificate does not contain a properly-formatted
     *                                     attestation extension, if it contains multiple attestation extensions, or if the
     *                                     attestation extension can not be parsed.
     */

    public static Attestation loadFromCertificate(X509Certificate x509Cert) throws CertificateParsingException {
        if (x509Cert.getExtensionValue(KNOX_EXTENSION_OID) == null
                && x509Cert.getExtensionValue(EAT_OID) == null
                && x509Cert.getExtensionValue(ASN1_OID) == null) {
            throw new CertificateParsingException("No attestation extensions found");
        }
        if (x509Cert.getExtensionValue(KNOX_EXTENSION_OID) != null) {
            if (x509Cert.getExtensionValue(EAT_OID) != null) {
                throw new CertificateParsingException("Multiple attestation extensions found");
            }
            return new KnoxAttestation(x509Cert);
        }
        if (x509Cert.getExtensionValue(EAT_OID) != null) {
            if (x509Cert.getExtensionValue(ASN1_OID) != null) {
                throw new CertificateParsingException("Multiple attestation extensions found");
            }
            try {
                return new EatAttestation(x509Cert);
            } catch (CborException cbe) {
                throw new CertificateParsingException("Unable to parse EAT extension", cbe);
            }
        }
        if (x509Cert.getExtensionValue(CRL_DP_OID) != null) {
            Log.w(AppApplication.TAG,
                    "CRL Distribution Points extension found in leaf certificate.");
        }
        return new Asn1Attestation(x509Cert);
    }

    Attestation(X509Certificate x509Cert) {
        unexpectedExtensionOids = retrieveUnexpectedExtensionOids(x509Cert);
    }

    public static String securityLevelToString(int attestationSecurityLevel) {
        switch (attestationSecurityLevel) {
            case KM_SECURITY_LEVEL_SOFTWARE:
                return "Software";
            case KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT:
                return "TEE";
            case KM_SECURITY_LEVEL_STRONG_BOX:
                return "StrongBox";
            default:
                return "Unkown (" + attestationSecurityLevel + ")";
        }
    }

    public static String attestationVersionToString(int version) {
        switch (version) {
            case 1:
                return "Keymaster version 2.0";
            case 2:
                return "Keymaster version 3.0";
            case 3:
                return "Keymaster version 4.0";
            case 4:
                return "Keymaster version 4.1";
            case 100:
                return "KeyMint version 1.0";
            case 200:
                return "KeyMint version 2.0";
            case 300:
                return "KeyMint version 3.0";
            default:
                return "Unkown (" + version + ")";
        }
    }

    public static String keymasterVersionToString(int version) {
        switch (version) {
            case 0:
                return "Keymaster version 0.2 or 0.3";
            case 1:
                return "Keymaster version 1.0";
            case 2:
                return "Keymaster version 2.0";
            case 3:
                return "Keymaster version 3.0";
            case 4:
                return "Keymaster version 4.0";
            case 41:
                return "Keymaster version 4.1";
            case 100:
                return "KeyMint version 1.0";
            case 200:
                return "KeyMint version 2.0";
            case 300:
                return "KeyMint version 3.0";
            default:
                return "Unkown (" + version + ")";
        }
    }

    public int getAttestationVersion() {
        return attestationVersion;
    }

    public abstract int getAttestationSecurityLevel();

    public abstract RootOfTrust getRootOfTrust();

    // Returns one of the KM_VERSION_* values define above.
    public int getKeymasterVersion() {
        return keymasterVersion;
    }

    public int getKeymasterSecurityLevel() {
        return keymasterSecurityLevel;
    }

    public byte[] getAttestationChallenge() {
        return attestationChallenge;
    }

    public byte[] getUniqueId() {
        return uniqueId;
    }

    public AuthorizationList getSoftwareEnforced() {
        return softwareEnforced;
    }

    public AuthorizationList getTeeEnforced() {
        return teeEnforced;
    }

    public Set<String> getUnexpectedExtensionOids() {
        return unexpectedExtensionOids;
    }

    @Override
    public String toString() {
        StringBuilder s = new StringBuilder();
        s.append("Extension type: " + getClass());
        s.append("\nAttest version: " + attestationVersionToString(attestationVersion));
        s.append("\nAttest security: " + securityLevelToString(getAttestationSecurityLevel()));
        s.append("\nKM version: " + keymasterVersionToString(keymasterVersion));
        s.append("\nKM security: " + securityLevelToString(keymasterSecurityLevel));

        s.append("\nChallenge");
        String stringChallenge =
                attestationChallenge != null ? new String(attestationChallenge) : "null";
        if (CharMatcher.ascii().matchesAllOf(stringChallenge)) {
            s.append(": [" + stringChallenge + "]");
        } else {
            s.append(" (base64): [" + BaseEncoding.base64().encode(attestationChallenge) + "]");
        }
        if (uniqueId != null) {
            s.append("\nUnique ID (base64): [" + BaseEncoding.base64().encode(uniqueId) + "]");
        }

        s.append("\n-- SW enforced --");
        s.append(softwareEnforced);
        s.append("\n-- TEE enforced --");
        s.append(teeEnforced);

        return s.toString();
    }

    Set<String> retrieveUnexpectedExtensionOids(X509Certificate x509Cert) {
        return new ImmutableSet.Builder<String>()
                .addAll(x509Cert.getCriticalExtensionOIDs()
                        .stream()
                        .filter(s -> !KEY_USAGE_OID.equals(s))
                        .iterator())
                .addAll(x509Cert.getNonCriticalExtensionOIDs()
                        .stream()
                        .filter(s -> !ASN1_OID.equals(s) && !EAT_OID.equals(s))
                        .iterator())
                .build();
    }
}
