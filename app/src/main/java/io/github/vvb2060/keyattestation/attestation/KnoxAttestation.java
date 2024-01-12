package io.github.vvb2060.keyattestation.attestation;

import android.os.Build;
import android.os.SystemProperties;
import android.text.TextUtils;
import android.util.Log;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1TaggedObject;

import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import io.github.vvb2060.keyattestation.AppApplication;

public class KnoxAttestation extends Asn1Attestation {
    static final String RO_PRODUCT_FIRST_API = "ro.product.first_api_level";
    static final int KNOX_TEE_PROPERTIES_INTEGRITY_STATUS = 5;

    IntegrityStatus mKnoxIntegrity;

    /**
     * Constructs a {@code KnoxAttestation} object from the provided {@link X509Certificate},
     * extracting the attestation data from the attestation extension.
     *
     * @param x509Cert
     * @throws CertificateParsingException if the certificate does not contain a properly-formatted
     *                                     attestation extension.
     */
    public KnoxAttestation(X509Certificate x509Cert) throws CertificateParsingException {
        super(x509Cert);
        ASN1Sequence knoxExtSeq = getKnoxExtensionSequence(x509Cert);

        if (knoxExtSeq != null) {
            for (int i = 0; i < knoxExtSeq.size(); i++) {
                if (knoxExtSeq.getObjectAt(i) instanceof ASN1TaggedObject entry) {
                    if (entry.getTagNo() == KNOX_TEE_PROPERTIES_INTEGRITY_STATUS) {
                        mKnoxIntegrity = new IntegrityStatus(entry.getBaseObject().toASN1Primitive());
                        break;
                    }
                }
            }
        }

        teeEnforced.setIntegrityStatus(mKnoxIntegrity);
    }

    ASN1Sequence getKnoxExtensionSequence(X509Certificate x509Cert)
            throws CertificateParsingException {
        byte[] knoxExtensionSequence = x509Cert.getExtensionValue(Attestation.KNOX_EXTENSION_OID);
        if (knoxExtensionSequence == null) {
            Log.e(AppApplication.TAG, "getKnoxExtensionSequence : not include knox extension");
            return null;
        }

        String value = bytesToHex(knoxExtensionSequence);

        int lengthOfExtension = Integer.parseInt(value.substring(2, 4), 16);
        int lengthOfValue = Integer.parseInt(value.substring(10, 12), 16);
        String firstApiLevel = SystemProperties.get(RO_PRODUCT_FIRST_API);

        if (!TextUtils.isEmpty(firstApiLevel)
                && Integer.parseInt(firstApiLevel) < Build.VERSION_CODES.O) {
            if (lengthOfExtension - 4 != lengthOfValue) {
                byte[] copy = new byte[lengthOfValue + 6];
                System.arraycopy(knoxExtensionSequence, 0,
                        copy, 0, lengthOfValue + 6);
                System.arraycopy(Integer.toHexString(lengthOfValue + 4).getBytes(), 1,
                        copy, 1, 1);
                System.arraycopy(Integer.toHexString(lengthOfValue + 2).getBytes(), 1,
                        copy, 3, 1);
                knoxExtensionSequence = copy;
            }
        }

        if (knoxExtensionSequence == null || knoxExtensionSequence.length == 0) {
            throw new CertificateParsingException("Did not find extension with OID "
                    + KNOX_EXTENSION_OID);
        }
        return Asn1Utils.getAsn1SequenceFromBytes(knoxExtensionSequence);
    }

    private String bytesToHex(byte[] a) {
        StringBuilder sb = new StringBuilder();
        for (byte b : a) {
            sb.append(String.format("%02x", Integer.valueOf(b & 255)));
        }
        return sb.toString();
    }
}
