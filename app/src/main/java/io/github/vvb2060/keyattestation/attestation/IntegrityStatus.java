package io.github.vvb2060.keyattestation.attestation;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

import java.security.cert.CertificateParsingException;

public class IntegrityStatus {
    private static final int TRUST_BOOT = 0;
    private static final int WARRANTY = 1;
    private static final int ICD = 2;
    private static final int KERNEL_STATUS = 3;
    private static final int SYSTEM_STATUS = 4;
    private static final int AUTH_RESULT = 5;

    public static final int STATUS_NORMAL = 0;
    public static final int STATUS_ABNORMAL = 1;
    public static final int STATUS_NOT_SUPPORT = 2;

    private int trustBoot = STATUS_NOT_SUPPORT;
    private int warranty = STATUS_NOT_SUPPORT;
    private int icd = STATUS_NOT_SUPPORT;
    private int kernelStatus = STATUS_NOT_SUPPORT;
    private int systemStatus = STATUS_NOT_SUPPORT;
    private AuthResult authResult;

    public IntegrityStatus(ASN1Encodable asn1Encodable) throws CertificateParsingException {
        if (!(asn1Encodable instanceof ASN1Sequence sequence)) {
            throw new CertificateParsingException("Expected sequence for integrity status, found "
                    + asn1Encodable.getClass().getName());
        }
        for (var entry : sequence) {
            if (!(entry instanceof ASN1TaggedObject taggedObject)) {
                throw new CertificateParsingException(
                        "Expected tagged object, found " + entry.getClass().getName());
            }
            int tag = taggedObject.getTagNo();
            var value = taggedObject.getBaseObject().toASN1Primitive();
            switch (tag) {
                case TRUST_BOOT -> trustBoot = Asn1Utils.getIntegerFromAsn1(value);
                case WARRANTY -> warranty = Asn1Utils.getIntegerFromAsn1(value);
                case ICD -> icd = Asn1Utils.getIntegerFromAsn1(value);
                case KERNEL_STATUS -> kernelStatus = Asn1Utils.getIntegerFromAsn1(value);
                case SYSTEM_STATUS -> systemStatus = Asn1Utils.getIntegerFromAsn1(value);
                case AUTH_RESULT -> authResult = AuthResult.parse(value);
                default -> throw new CertificateParsingException("invalid tag no: " + tag);
            }
        }
    }

    public static String statusToString(int status) {
        return switch (status) {
            case STATUS_NORMAL -> "Normal";
            case STATUS_ABNORMAL -> "Abnormal";
            case STATUS_NOT_SUPPORT -> "Not support";
            default -> Integer.toHexString(status);
        };
    }

    @Override
    public String toString() {
        return "TrustBoot: " + statusToString(trustBoot) +
                "\nWarranty: " + statusToString(warranty) +
                "\nICD: " + statusToString(icd) +
                "\nKernel Status: " + statusToString(kernelStatus) +
                "\nSystem Status: " + statusToString(systemStatus) +
                "\nCaller auth(with PROCA) Status: " +
                (authResult == null ? "Not performed" : authResult.toString());
    }
}
