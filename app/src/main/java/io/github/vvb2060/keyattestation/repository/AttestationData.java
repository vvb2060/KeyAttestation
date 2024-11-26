package io.github.vvb2060.keyattestation.repository;

import static io.github.vvb2060.keyattestation.attestation.Attestation.KM_SECURITY_LEVEL_SOFTWARE;
import static io.github.vvb2060.keyattestation.lang.AttestationException.CODE_CANT_PARSE_CERT;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import io.github.vvb2060.keyattestation.attestation.Attestation;
import io.github.vvb2060.keyattestation.attestation.CertificateInfo;
import io.github.vvb2060.keyattestation.attestation.RootOfTrust;
import io.github.vvb2060.keyattestation.lang.AttestationException;

public class AttestationData {
    private final List<CertificateInfo> certs;
    private final RootOfTrust rootOfTrust;
    private final int status;
    private final boolean sw;
    public Attestation showAttestation;

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

    private AttestationData(List<CertificateInfo> certs) {
        this.certs = certs;

        var info = certs.get(certs.size() - 1);
        var attestation = info.getAttestation();
        if (attestation != null) {
            this.showAttestation = attestation;
            this.rootOfTrust = attestation.getRootOfTrust();
            this.sw = attestation.getAttestationSecurityLevel() == KM_SECURITY_LEVEL_SOFTWARE;
        } else {
            throw new AttestationException(CODE_CANT_PARSE_CERT, info.getCertException());
        }

        var status = certs.get(0).getIssuer();
        for (var cert : certs) {
            if (cert.getStatus() < CertificateInfo.CERT_EXPIRED) {
                status = CertificateInfo.KEY_FAILED;
                break;
            }
        }
        if (status == CertificateInfo.KEY_GOOGLE) {
            for (int i = 1; i < certs.size(); i++) {
                if (certs.get(i).getCert().getSubjectX500Principal().getName().contains("Google LLC")) {
                    continue;
                }
                if (certs.get(i).getCertsIssued() != null) {
                    status = CertificateInfo.KEY_GOOGLE_RKP;
                }
                break;
            }
        }
        this.status = status;
    }

    private static List<X509Certificate> sortCerts(List<X509Certificate> certs) {
        if (certs.size() < 2) {
            return certs;
        }

        var issuer = certs.get(0).getIssuerX500Principal();
        boolean okay = true;
        for (var cert : certs) {
            var subject = cert.getSubjectX500Principal();
            if (issuer.equals(subject)) {
                issuer = subject;
            } else {
                okay = false;
                break;
            }
        }
        if (okay) {
            return certs;
        }

        var newList = new ArrayList<X509Certificate>(certs.size());
        for (var cert : certs) {
            boolean found = false;
            var subject = cert.getSubjectX500Principal();
            for (var c : certs) {
                if (c == cert) continue;
                if (c.getIssuerX500Principal().equals(subject)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                newList.add(cert);
            }
        }
        if (newList.size() != 1) {
            return certs;
        }

        var oldList = new LinkedList<>(certs);
        oldList.remove(newList.get(0));
        for (int i = 0; i < newList.size(); i++) {
            issuer = newList.get(i).getIssuerX500Principal();
            for (var it = oldList.iterator(); it.hasNext(); ) {
                var cert = it.next();
                if (cert.getSubjectX500Principal().equals(issuer)) {
                    newList.add(cert);
                    it.remove();
                    break;
                }
            }
        }
        if (!oldList.isEmpty()) {
            return certs;
        }
        return newList;
    }

    static AttestationData parseCertificateChain(List<X509Certificate> certs) {
        var infoList = new ArrayList<CertificateInfo>();
        CertificateInfo.parse(sortCerts(certs), infoList);
        return new AttestationData(infoList);
    }

}
