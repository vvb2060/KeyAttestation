package com.samsung.android.security.keystore;

import android.content.Context;
import androidx.annotation.RequiresApi;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.ProviderException;
import java.security.cert.Certificate;

@RequiresApi(28)
public class AttestationUtils {
    public static final String DEFAULT_KEYSTORE = "AndroidKeyStore";
    public static final String PUBKEY_DIGEST_ALGORITHM = "SHA-256";

    public Iterable<byte[]> attestKey(String alias, byte[] challenge)
            throws IllegalArgumentException, ProviderException, NullPointerException {
        throw new RuntimeException("Stub!");
    }

    @RequiresApi(29)
    public Iterable<byte[]> attestKey(AttestParameterSpec spec)
            throws IllegalArgumentException, ProviderException, NullPointerException {
        throw new RuntimeException("Stub!");
    }

    public Iterable<byte[]> attestDevice(String alias, byte[] challenge)
            throws IllegalArgumentException, ProviderException, NullPointerException,
            DeviceIdAttestationException {
        throw new RuntimeException("Stub!");
    }

    @RequiresApi(29)
    public Iterable<byte[]> attestDevice(AttestParameterSpec spec)
            throws IllegalArgumentException, ProviderException, NullPointerException,
            DeviceIdAttestationException {
        throw new RuntimeException("Stub!");
    }

    public void storeCertificateChain(String alias, Iterable<byte[]> iterable)
            throws KeyStoreException, NullPointerException, ProviderException {
        throw new RuntimeException("Stub!");
    }

    @RequiresApi(29)
    public KeyPair generateKeyPair(String alias, byte[] challenge)
            throws IllegalArgumentException, ProviderException, NullPointerException {
        throw new RuntimeException("Stub!");
    }

    @RequiresApi(29)
    public KeyPair generateKeyPair(AttestParameterSpec spec)
            throws IllegalArgumentException, ProviderException, NullPointerException {
        throw new RuntimeException("Stub!");
    }

    @RequiresApi(29)
    public Certificate[] getCertificateChain(String alias) {
        throw new RuntimeException("Stub!");
    }

    @RequiresApi(29)
    public Key getKey(String alias) throws KeyStoreException {
        throw new RuntimeException("Stub!");
    }

    @RequiresApi(29)
    public void deleteKey(String alias) throws KeyStoreException {
        throw new RuntimeException("Stub!");
    }

    @RequiresApi(33)
    public boolean isSupportDeviceAttestation(Context context) {
        throw new RuntimeException("Stub!");
    }
}
