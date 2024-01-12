package io.github.vvb2060.keyattestation.attestation;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1TaggedObject;

import java.io.IOException;
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

    private int trustBoot;
    private int warranty;
    private int icd;
    private int kernelStatus;
    private int systemStatus;
    private AuthResult authResult;

    public IntegrityStatus(ASN1Encodable asn1Encodable) throws CertificateParsingException {
        if (!(asn1Encodable instanceof ASN1Sequence sequence)) {
            throw new CertificateParsingException("Expected sequence for integrity status, found "
                    + asn1Encodable.getClass().getName());
        }

        ASN1SequenceParser parser = sequence.parser();
        ASN1TaggedObject entry = parseAsn1TaggedObject(parser);

        for (; entry != null; entry = parseAsn1TaggedObject(parser)) {
            int tag = entry.getTagNo();
            ASN1Primitive value = entry.getBaseObject().toASN1Primitive();

            switch (tag) {
                case TRUST_BOOT:
                    trustBoot = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case WARRANTY:
                    warranty = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case ICD:
                    icd = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case KERNEL_STATUS:
                    kernelStatus = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case SYSTEM_STATUS:
                    systemStatus = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case AUTH_RESULT:
                    authResult = new AuthResult(value);
                    break;
            }
        }
    }

    private static ASN1TaggedObject parseAsn1TaggedObject(ASN1SequenceParser parser)
            throws CertificateParsingException {
        ASN1Encodable asn1Encodable = parseAsn1Encodable(parser);
        if (asn1Encodable == null || asn1Encodable instanceof ASN1TaggedObject) {
            return (ASN1TaggedObject) asn1Encodable;
        }
        throw new CertificateParsingException(
                "Expected tagged object, found " + asn1Encodable.getClass().getName());
    }

    private static ASN1Encodable parseAsn1Encodable(ASN1SequenceParser parser)
            throws CertificateParsingException {
        try {
            return parser.readObject();
        } catch (IOException e) {
            throw new CertificateParsingException("Failed to parse ASN1 sequence", e);
        }
    }

    public AuthResult getAuthResult() {
        return authResult;
    }

    public String statusToString(int status) {
        switch (status) {
            case STATUS_NORMAL:
                return "Normal";
            case STATUS_ABNORMAL:
                return "Abnormal";
            case STATUS_NOT_SUPPORT:
                return "Not support";
            default:
                return Integer.toHexString(status);
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("Trustboot: ")
                .append(statusToString(trustBoot)).append('\n')
                .append("Warranty bit: ")
                .append(statusToString(warranty)).append('\n')
                .append("ICD: ")
                .append(statusToString(icd)).append('\n')
                .append("Kernel status: ")
                .append(statusToString(kernelStatus)).append('\n')
                .append("System status: ")
                .append(statusToString(systemStatus));
        return sb.toString();
    }
}
