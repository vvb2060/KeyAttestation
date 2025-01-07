package com.samsung.android.security.keystore;

import android.annotation.TargetApi;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;

@TargetApi(Build.VERSION_CODES.Q)
public class AttestParameterSpec {
    public boolean isDeviceAttestation() {
        throw new RuntimeException("Stub!");
    }

    public static class Builder {
        public Builder(String alias, byte[] challenge) {
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

        public Builder setPackageName(String packageName) {
            throw new RuntimeException("Stub!");
        }

        public Builder setKeyGenParameterSpec(KeyGenParameterSpec spec) {
            throw new RuntimeException("Stub!");
        }

        public AttestParameterSpec build() {
            throw new RuntimeException("Stub!");
        }
    }
}
