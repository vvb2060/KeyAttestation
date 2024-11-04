package android.security.keystore;

import android.content.Context;

import java.security.cert.X509Certificate;

public abstract class AttestationUtils {
    public static X509Certificate[] attestDeviceIds(Context context,
                                                    int[] idTypes,
                                                    byte[] attestationChallenge
    ) throws DeviceIdAttestationException {
        throw new RuntimeException("Stub!");
    }
}
