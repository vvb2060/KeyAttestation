package io.github.vvb2060.keyattestation.attestation;

import com.google.common.io.BaseEncoding;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

// https://docs.samsungknox.com/dev/knox-attestation/
public class KnoxAttestation extends Asn1Attestation {
    private static final int CHALLENGE = 0;
    private static final int ID_ATTEST = 4;
    private static final int INTEGRITY = 5;
    private static final int ATTESTATION_RECORD_HASH = 6;

    private String challenge;
    private String idAttest;
    private IntegrityStatus knoxIntegrity;
    private byte[] recordHash;

    public KnoxAttestation(X509Certificate x509Cert) throws CertificateParsingException {
        super(x509Cert);
        ASN1Sequence knoxExtSeq = getKnoxExtensionSequence(x509Cert);
        for (var entry : knoxExtSeq) {
            if (!(entry instanceof ASN1TaggedObject taggedObject)) {
                throw new CertificateParsingException(
                        "Expected tagged object, found " + entry.getClass().getName());
            }
            int tag = taggedObject.getTagNo();
            var value = taggedObject.getBaseObject().toASN1Primitive();
            switch (tag) {
                case CHALLENGE -> challenge = Asn1Utils.getStringFromASN1PrintableString(value);
                case ID_ATTEST -> idAttest = Asn1Utils.getStringFromASN1PrintableString(value);
                case INTEGRITY -> knoxIntegrity = new IntegrityStatus(value);
                case ATTESTATION_RECORD_HASH -> recordHash = Asn1Utils.getByteArrayFromAsn1(value);
                default -> throw new CertificateParsingException("invalid tag no: " + tag);
            }
        }
    }

    ASN1Sequence getKnoxExtensionSequence(X509Certificate x509Cert)
            throws CertificateParsingException {
        byte[] knoxExtensionSequence = x509Cert.getExtensionValue(KNOX_OID);
        if (knoxExtensionSequence == null || knoxExtensionSequence.length == 0) {
            throw new CertificateParsingException("Did not find extension with OID " + KNOX_OID);
        }
        return Asn1Utils.getAsn1SequenceFromBytes(knoxExtensionSequence);
    }

    public String getKnoxChallenge() {
        return challenge;
    }

    public String getIdAttest() {
        return idAttest;
    }

    public IntegrityStatus getKnoxIntegrity() {
        return knoxIntegrity;
    }

    public byte[] getRecordHash() {
        return recordHash;
    }

    @Override
    public String toString() {
        return super.toString() +
                "\n\nExtension type: " + getClass().getSimpleName() +
                "\nID attestation: " + idAttest +
                "\nChallenge: " + challenge +
                "\nIntegrity status: " + knoxIntegrity +
                "\nAttestation record hash: " + BaseEncoding.base16().lowerCase().encode(recordHash);
    }
}
