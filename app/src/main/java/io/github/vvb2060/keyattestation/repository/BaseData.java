package io.github.vvb2060.keyattestation.repository;

import java.util.List;

import io.github.vvb2060.keyattestation.attestation.CertificateInfo;
import io.github.vvb2060.keyattestation.attestation.RootPublicKey;

public abstract class BaseData {
    protected List<CertificateInfo> certs;
    protected RootPublicKey.Status status;

    protected void init(List<CertificateInfo> certs) {
        this.certs = certs;
        if (certs.isEmpty()) {
            this.status = RootPublicKey.Status.NULL;
            return;
        }

        var status = certs.get(0).getIssuer();
        for (var cert : certs) {
            if (cert.getStatus() < CertificateInfo.CERT_EXPIRED) {
                status = RootPublicKey.Status.FAILED;
                break;
            }
        }
        if (status == RootPublicKey.Status.GOOGLE) {
            for (int i = 1; i < certs.size(); i++) {
                if (certs.get(i).getCert().getSubjectX500Principal().getName().contains("Google LLC")) {
                    continue;
                }
                if (certs.get(i).getProvisioningInfo() != null) {
                    status = RootPublicKey.Status.GOOGLE_RKP;
                }
                break;
            }
        }
        this.status = status;
    }

    public List<CertificateInfo> getCerts() {
        return certs;
    }

    public RootPublicKey.Status getStatus() {
        return status;
    }
}
