package io.github.vvb2060.keyattestation;

import android.content.res.Resources;
import android.util.Log;

import com.google.android.attestation.AttestationApplicationId;
import com.google.android.attestation.AttestationApplicationId.AttestationPackageInfo;
import com.google.android.attestation.AuthorizationList;
import com.google.android.attestation.CertificateRevocationStatus;
import com.google.android.attestation.ParsedAttestationRecord;
import com.google.android.attestation.RootOfTrust;

import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;

import static com.google.android.attestation.Constants.GOOGLE_ROOT_CERTIFICATE;
import static com.google.android.attestation.ParsedAttestationRecord.createParsedAttestationRecord;
import static java.nio.charset.StandardCharsets.UTF_8;

@SuppressWarnings("OptionalUsedAsFieldOrParameterType")
public class KeyAttestation {

    private static final String TAG = KeyAttestation.class.getCanonicalName();
    private static final StringBuilder sb = new StringBuilder();

    private static void print(String str) {
        sb.append(str).append('\n');
    }

    public static String parseAttestationRecord(X509Certificate[] certs) throws IOException {
        sb.delete(0, sb.length());

        ParsedAttestationRecord parsedAttestationRecord = createParsedAttestationRecord(certs[0]);

        print("Attestation version: " + parsedAttestationRecord.attestationVersion);
        print("Attestation Security Level: " + parsedAttestationRecord.attestationSecurityLevel.name());
        print("Keymaster Version: " + parsedAttestationRecord.keymasterVersion);
        print("Keymaster Security Level: " + parsedAttestationRecord.keymasterSecurityLevel.name());

        print("Attestation Challenge: " + new String(parsedAttestationRecord.attestationChallenge, UTF_8));
        print("Unique ID: " + Arrays.toString(parsedAttestationRecord.uniqueId));

        print("Software Enforced Authorization List:");
        AuthorizationList softwareEnforced = parsedAttestationRecord.softwareEnforced;
        printAuthorizationList(softwareEnforced, parsedAttestationRecord.attestationVersion, "    ");

        print("TEE Enforced Authorization List:");
        AuthorizationList teeEnforced = parsedAttestationRecord.teeEnforced;
        printAuthorizationList(teeEnforced, parsedAttestationRecord.attestationVersion, "    ");
        return sb.toString();
    }

    private static void printAuthorizationList(AuthorizationList authorizationList, int attestationVersion, String indent) {
        // Detailed explanation of the keys and their values can be found here:
        // https://source.android.com/security/keystore/tags
        printOptional(authorizationList.purpose, indent + "Purpose(s)");
        printOptional(authorizationList.algorithm, indent + "Algorithm");
        printOptional(authorizationList.keySize, indent + "Key Size");
        printOptional(authorizationList.digest, indent + "Digest");
        printOptional(authorizationList.padding, indent + "Padding");
        printOptional(authorizationList.ecCurve, indent + "EC Curve");
        printOptional(authorizationList.rsaPublicExponent, indent + "RSA Public Exponent");
        if (attestationVersion >= 3) {
            print(indent + "Rollback Resistance: " + authorizationList.rollbackResistance);
        } else {
            print(indent + "Rollback Resistant: " + authorizationList.rollbackResistant);
        }
        printOptional(authorizationList.activeDateTime, indent + "Active DateTime");
        printOptional(authorizationList.originationExpireDateTime, indent + "Origination Expire DateTime");
        printOptional(authorizationList.usageExpireDateTime, indent + "Usage Expire DateTime");
        print(indent + "No Auth Required: " + authorizationList.noAuthRequired);
        printOptional(authorizationList.userAuthType, indent + "User Auth Type");
        printOptional(authorizationList.authTimeout, indent + "Auth Timeout");
        print(indent + "Allow While On Body: " + authorizationList.allowWhileOnBody);
        if (attestationVersion >= 3) {
            print(indent + "Trusted User Presence Required: " + authorizationList.trustedUserPresenceRequired);
            print(indent + "Trusted Confirmation Required: " + authorizationList.trustedConfirmationRequired);
            print(indent + "Unlocked Device Required: " + authorizationList.unlockedDeviceRequired);
        }
        print(indent + "All Applications: " + authorizationList.allApplications);
        printOptional(authorizationList.applicationId, indent + "Application ID");
        printOptional(authorizationList.creationDateTime, indent + "Creation DateTime");
        printOptional(authorizationList.origin, indent + "Origin");

        if (authorizationList.rootOfTrust.isPresent()) {
            print(indent + "Root Of Trust:");
            printRootOfTrust(authorizationList.rootOfTrust, attestationVersion, indent + "\t");
        }
        printOptional(authorizationList.osVersion, indent + "OS Version");
        printOptional(authorizationList.osPatchLevel, indent + "OS Patch Level");
        if (authorizationList.attestationApplicationId.isPresent()) {
            print(indent + "Attestation Application ID:");
            printAttestationApplicationId(authorizationList.attestationApplicationId, indent + "    ");
        }
        printOptional(authorizationList.attestationApplicationIdBytes, indent + "Attestation Application ID Bytes");
        printOptional(authorizationList.attestationIdBrand, indent + "Attestation ID Brand");
        printOptional(authorizationList.attestationIdDevice, indent + "Attestation ID Device");
        printOptional(authorizationList.attestationIdProduct, indent + "Attestation ID Product");
        printOptional(authorizationList.attestationIdSerial, indent + "Attestation ID Serial");
        printOptional(authorizationList.attestationIdImei, indent + "Attestation ID IMEI");
        printOptional(authorizationList.attestationIdMeid, indent + "Attestation ID MEID");
        printOptional(authorizationList.attestationIdManufacturer, indent + "Attestation ID Manufacturer");
        printOptional(authorizationList.attestationIdModel, indent + "Attestation ID Model");
        printOptional(authorizationList.vendorPatchLevel, indent + "Vendor Patch Level");
        printOptional(authorizationList.bootPatchLevel, indent + "Boot Patch Level");
    }

    private static void printRootOfTrust(Optional<RootOfTrust> rootOfTrust, int attestationVersion, String indent) {
        if (rootOfTrust.isPresent()) {
            print(indent + "Verified Boot Key: " + Base64.toBase64String(rootOfTrust.get().verifiedBootKey));
            print(indent + "Device Locked: " + rootOfTrust.get().deviceLocked);
            print(indent + "Verified Boot State: " + rootOfTrust.get().verifiedBootState.name());
            if (attestationVersion >= 3) {
                print(indent + "Verified Boot Hash: " + Base64.toBase64String(rootOfTrust.get().verifiedBootHash));
            }
        }
    }

    private static void printAttestationApplicationId(Optional<AttestationApplicationId> attestationApplicationId, String indent) {
        if (attestationApplicationId.isPresent()) {
            print(indent + "Package Infos (<package name>, <version>): ");
            for (AttestationPackageInfo info : attestationApplicationId.get().packageInfos) {
                print(indent + "    " + info.packageName + ", " + info.version);
            }
            print(indent + "Signature Digests:");
            for (byte[] digest : attestationApplicationId.get().signatureDigests) {
                print(indent + "    " + Base64.toBase64String(digest));
            }
        }
    }

    private static <T> void printOptional(Optional<T> optional, String caption) {
        if (optional.isPresent()) {
            if (optional.get() instanceof byte[]) {
                print(caption + ": " + Base64.toBase64String((byte[]) optional.get()));
            } else {
                print(caption + ": " + optional.get());
            }
        }
    }

    static void verifyCertificateChain(StringBuilder sb, X509Certificate[] certs, Resources resources) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        X509Certificate parent = certs[certs.length - 1];
        for (int i = certs.length - 1; i >= 0; i--) {
            X509Certificate cert = certs[i];
            // Verify that the certificate has not expired.
            cert.checkValidity();
            cert.verify(parent.getPublicKey());
            parent = cert;
            try {
                CertificateRevocationStatus certStatus = CertificateRevocationStatus
                        .fetchStatus(cert.getSerialNumber());
                if (certStatus != null) {
                    throw new CertificateException("Certificate revocation status is " + certStatus.status.name());
                }
            } catch (IOException e) {
                Log.w(TAG, "Unable to fetch certificate revocation status. Fall back to using built-in data.", e);
                sb.append("Unable to fetch certificate revocation status. Fall back to using built-in data.\n");
                InputStreamReader reader = new InputStreamReader(resources.openRawResource(R.raw.status));
                CertificateRevocationStatus certStatus = CertificateRevocationStatus
                        .loadStatusFromFile(cert.getSerialNumber(), reader);
                if (certStatus != null) {
                    throw new CertificateException("Certificate revocation status is " + certStatus.status.name());
                }
            }
        }

        // If the attestation is trustworthy and the device ships with hardware-
        // level key attestation, Android 7.0 (API level 24) or higher, and
        // Google Play services, the root certificate should be signed with the
        // Google attestation root key.
        X509Certificate secureRoot = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(GOOGLE_ROOT_CERTIFICATE.getBytes(UTF_8)));
        if (Arrays.equals(secureRoot.getTBSCertificate(), certs[certs.length - 1].getTBSCertificate())) {
            sb.append("The root certificate is correct, so this attestation is trustworthy, as long as none of"
                    + " the certificates in the chain have been revoked. A production-level system"
                    + " should check the certificate revocation lists using the distribution points that"
                    + " are listed in the intermediate and root certificates. \n\n\n");
        } else {
            sb.append("The root certificate is NOT correct. The attestation was probably generated by"
                    + " software, not in secure hardware. This means that, although the attestation"
                    + " contents are probably valid and correct, there is no proof that they are in fact"
                    + " correct. If you're using a production-level system, you should now treat the"
                    + " properties of this attestation certificate as advisory only, and you shouldn't"
                    + " rely on this attestation certificate to provide security guarantees. \n\n\n");
        }
    }

}
