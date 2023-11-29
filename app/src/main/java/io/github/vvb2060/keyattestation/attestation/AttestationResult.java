package io.github.vvb2060.keyattestation.attestation;

import static io.github.vvb2060.keyattestation.attestation.Attestation.KM_SECURITY_LEVEL_SOFTWARE;
import static io.github.vvb2060.keyattestation.lang.AttestationException.CODE_CANT_PARSE_CERT;

import java.util.List;

import io.github.vvb2060.keyattestation.lang.AttestationException;

public class AttestationResult {
    private final List<CertificateInfo> certs;
    private RootOfTrust rootOfTrust;
    private int status = CertificateInfo.KEY_FAILED;
    private boolean sw = true;
    public Attestation showAttestation;

    private AttestationResult(List<CertificateInfo> certs) {
        this.certs = certs;
    }

    public List<CertificateInfo> getCerts() {
        return certs;
    }

    public RootOfTrust getRootOfTrust() {
        return rootOfTrust;
    }

    public int getStatus() {
        return status;
    }

    public boolean isSoftwareLevel() {
        return sw;
    }

    public static AttestationResult form(List<CertificateInfo> certs) {
        var result = new AttestationResult(certs);
        result.status = certs.get(0).getIssuer();
        for (var cert : certs) {
            if (cert.getStatus() < CertificateInfo.CERT_EXPIRED) {
                result.status = CertificateInfo.KEY_FAILED;
                break;
            }
        }
        var info = certs.get(certs.size() - 1);
        var attestation = info.getAttestation();
        if (attestation != null) {
            result.showAttestation = attestation;
            result.rootOfTrust = attestation.getRootOfTrust();
            result.sw = attestation.getAttestationSecurityLevel() == KM_SECURITY_LEVEL_SOFTWARE;
        } else {
            throw new AttestationException(CODE_CANT_PARSE_CERT, info.getCertException());
        }
        return result;
    }
}
