package io.github.vvb2060.keyattestation.attestation;

import com.google.common.io.BaseEncoding;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1TaggedObject;

import java.io.IOException;
import java.security.cert.CertificateParsingException;

public class AuthResult {
    private static final int CALLER_AUTH_RESULT = 0;
    private static final int CALLING_PACKAGE = 1;
    private static final int CALLING_PACKAGE_SIGS = 2;
    private static final int CALLING_PACKAGE_AUTH_RESULT = 3;

    public static final int STATUS_NORMAL = 0;
    public static final int STATUS_ABNORMAL = 1;
    public static final int STATUS_NOT_SUPPORT = 2;

    private int callerAuthResult;
    private byte[] callingPackage;
    private byte[] callingPackageSigs;
    private int callingPackageAuthResult;

    public AuthResult(ASN1Encodable asn1Encodable) throws CertificateParsingException {
        if (!(asn1Encodable instanceof ASN1Sequence sequence)) {
            throw new CertificateParsingException("Expected sequence for caller auth, found "
                    + asn1Encodable.getClass().getName());
        }

        ASN1SequenceParser parser = sequence.parser();
        ASN1TaggedObject entry = parseAsn1TaggedObject(parser);

        for (; entry != null; entry = parseAsn1TaggedObject(parser)) {
            int tag = entry.getTagNo();
            ASN1Primitive value = entry.getBaseObject().toASN1Primitive();

            switch (tag) {
                case CALLER_AUTH_RESULT:
                    callerAuthResult = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case CALLING_PACKAGE:
                    callingPackage = Asn1Utils.getByteArrayFromAsn1(value);
                    break;
                case CALLING_PACKAGE_SIGS:
                    callingPackageSigs = Asn1Utils.getByteArrayFromAsn1(value);
                    break;
                case CALLING_PACKAGE_AUTH_RESULT:
                    callingPackageAuthResult = Asn1Utils.getIntegerFromAsn1(value);
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

    public String statusToString(int status, boolean isCallingPackageAuthResult) {
        switch (status) {
            case STATUS_NORMAL:
                return "Normal";
            case STATUS_ABNORMAL:
                return "Abnormal";
            case STATUS_NOT_SUPPORT:
                return "Not support";
            default:
                if (isCallingPackageAuthResult) {
                    return "Not support";
                }
                return Integer.toHexString(status);
        }
    }

    @Override
    public String toString() {
        try {
            StringBuilder sb = new StringBuilder("Caller auth result: ")
                    .append(statusToString(callerAuthResult, false)).append('\n')
                    .append("Calling package: ")
                    .append(new String(callingPackage)).append('\n')
                    .append("Calling package signatures: ")
                    .append(BaseEncoding.base64().encode(callingPackageSigs)).append(" (base64)").append('\n')
                    .append("Calling package auth result: ")
                    .append(statusToString(callingPackageAuthResult, true));
            return sb.toString();
        } catch (NullPointerException e) {
            return "Not performed";
        }
    }
}
