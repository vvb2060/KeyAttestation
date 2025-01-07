package com.samsung.android.security.keystore;

import android.annotation.TargetApi;
import android.os.Build;

@TargetApi(Build.VERSION_CODES.Q)
public class AttestationUtils {
    public static String DEFAULT_KEYSTORE = "AndroidKeyStore";

    public Iterable<byte[]> attestKey(AttestParameterSpec spec) {
        throw new RuntimeException("Stub!");
    }

    public Iterable<byte[]> attestDevice(AttestParameterSpec spec) {
        throw new RuntimeException("Stub!");
    }

    public void storeCertificateChain(String alias, Iterable<byte[]> iterable) {
        throw new RuntimeException("Stub!");
    }
}
