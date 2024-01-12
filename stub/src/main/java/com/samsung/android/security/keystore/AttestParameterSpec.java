package com.samsung.android.security.keystore;

import android.security.keystore.KeyGenParameterSpec;
import androidx.annotation.RequiresApi;
import javax.security.auth.x500.X500Principal;

@RequiresApi(29)
public class AttestParameterSpec {
    public AttestParameterSpec(String algorithm, byte[] challenge, boolean reqAttestDevice,
                               boolean checkIntegrity, boolean devicePropertiesAttestationIncluded,
                               String packageName, KeyGenParameterSpec spec,
                               X500Principal certificateSubject) {
        throw new RuntimeException("Stub!");
    }

    public AttestParameterSpec(String algorithm, byte[] challenge, boolean reqAttestDevice,
                               boolean checkIntegrity, String packageName, KeyGenParameterSpec spec,
                               X500Principal certificateSubject) {
        throw new RuntimeException("Stub!");
    }

    public String getAlgorithm() {
        throw new RuntimeException("Stub!");
    }

    public byte[] getChallenge() {
        throw new RuntimeException("Stub!");
    }

    public X500Principal getCertificateSubject() {
        throw new RuntimeException("Stub!");
    }

    public boolean isDeviceAttestation() {
        throw new RuntimeException("Stub!");
    }

    public boolean isVerifiableIntegrity() {
        throw new RuntimeException("Stub!");
    }

    @RequiresApi(33)
    public boolean isDevicePropertiesAttestationIncluded() {
        throw new RuntimeException("Stub!");
    }

    public String getPackageName() {
        throw new RuntimeException("Stub!");
    }

    public KeyGenParameterSpec getKeyGenParameterSpec() {
        throw new RuntimeException("Stub!");
    }

    public static final class Builder {
        public Builder(String alias, byte[] challenge) {
            throw new RuntimeException("Stub!");
        }

        public Builder(AttestParameterSpec sourceSpec) {
            throw new RuntimeException("Stub!");
        }

        public Builder setAlgorithm(String algorithm) {
            throw new RuntimeException("Stub!");
        }

        public Builder setDeviceAttestation(boolean requested) {
            throw new RuntimeException("Stub!");
        }

        public Builder setVerifiableIntegrity(boolean checked) {
            throw new RuntimeException("Stub!");
        }

        @RequiresApi(33)
        public Builder setDevicePropertiesAttestationIncluded(
                boolean devicePropertiesAttestationIncluded) {
            throw new RuntimeException("Stub!");
        }

        public Builder setPackageName(String packageName) {
            throw new RuntimeException("Stub!");
        }

        public Builder setKeyGenParameterSpec(KeyGenParameterSpec spec) {
            throw new RuntimeException("Stub!");
        }

        public Builder setCertificateSubject(X500Principal subject) {
            throw new RuntimeException("Stub!");
        }

        public AttestParameterSpec build() {
            throw new RuntimeException("Stub!");
        }
    }
}
