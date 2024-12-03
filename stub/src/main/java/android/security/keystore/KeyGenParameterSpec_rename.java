package android.security.keystore;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

public class KeyGenParameterSpec_rename {

    public static class Builder {
        public Builder(String keystoreAlias, int purposes) {
        }

        public Builder setAlgorithmParameterSpec(AlgorithmParameterSpec spec) {
            return this;
        }

        public Builder setCertificateSubject(X500Principal subject) {
            return this;
        }

        public Builder setCertificateSerialNumber(BigInteger serialNumber) {
            return this;
        }

        public Builder setCertificateNotBefore(Date date) {
            return this;
        }

        public Builder setCertificateNotAfter(Date date) {
            return this;
        }

        public Builder setDigests(String... digests) {
            return this;
        }

        public Builder setAttestationChallenge(byte[] attestationChallenge) {
            return this;
        }

        public Builder setDevicePropertiesAttestationIncluded(boolean devicePropertiesAttestationIncluded) {
            return this;
        }

        public Builder setAttestationIds(int[] attestationIds) {
            return this;
        }

        public Builder setUniqueIdIncluded(boolean uniqueIdIncluded) {
            return this;
        }

        public Builder setIsStrongBoxBacked(boolean isStrongBoxBacked) {
            return this;
        }

        public Builder setAttestKeyAlias(String attestKeyAlias) {
            return this;
        }

        public KeyGenParameterSpec_rename build() {
            throw new RuntimeException("Stub!");
        }
    }
}
