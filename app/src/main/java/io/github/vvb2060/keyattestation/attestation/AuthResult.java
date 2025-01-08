package io.github.vvb2060.keyattestation.attestation;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

import java.security.cert.CertificateParsingException;

public class AuthResult {
    private static final int CALLER_AUTH_RESULT = 0;
    private static final int CALLING_PACKAGE = 1;
    private static final int CALLING_PACKAGE_SIGS = 2;
    private static final int CALLING_PACKAGE_AUTH_RESULT = 3;

    private int callerAuthResult = IntegrityStatus.STATUS_NOT_SUPPORT;
    private String callingPackage;
    private String callingPackageSigs;
    private int callingPackageAuthResult = IntegrityStatus.STATUS_NOT_SUPPORT;

    public AuthResult(ASN1Encodable asn1Encodable) throws CertificateParsingException {
        if (!(asn1Encodable instanceof ASN1Sequence sequence)) {
            throw new CertificateParsingException("Expected sequence for caller auth, found "
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
                case CALLER_AUTH_RESULT -> callerAuthResult = Asn1Utils.getIntegerFromAsn1(value);
                case CALLING_PACKAGE ->
                        callingPackage = Asn1Utils.getStringFromASN1PrintableString(value);
                case CALLING_PACKAGE_SIGS ->
                        callingPackageSigs = Asn1Utils.getStringFromASN1PrintableString(value);
                case CALLING_PACKAGE_AUTH_RESULT ->
                        callingPackageAuthResult = Asn1Utils.getIntegerFromAsn1(value);
                default -> throw new CertificateParsingException("invalid tag no: " + tag);
            }
        }
    }

    @Override
    public String toString() {
        return "\nCaller Auth Result: " + IntegrityStatus.statusToString(callerAuthResult) +
                "\nCalling Package: " + callingPackage +
                "\nCalling Package Signatures: " + callingPackageSigs +
                "\nCalling Package Auth Result: " + IntegrityStatus.statusToString(callingPackageAuthResult);
    }

    public static AuthResult parse(ASN1Encodable asn1Encodable) throws CertificateParsingException {
        var auth = new AuthResult(asn1Encodable);
        if (auth.callerAuthResult == IntegrityStatus.STATUS_NOT_SUPPORT &&
                auth.callingPackage == null &&
                auth.callingPackageSigs == null &&
                auth.callingPackageAuthResult == IntegrityStatus.STATUS_NOT_SUPPORT) {
            return null;
        }
        return auth;
    }
}
