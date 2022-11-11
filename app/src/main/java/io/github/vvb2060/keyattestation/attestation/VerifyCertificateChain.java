package io.github.vvb2060.keyattestation.attestation;

import android.util.Base64;

import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import io.github.vvb2060.keyattestation.AppApplication;
import io.github.vvb2060.keyattestation.R;

public class VerifyCertificateChain {
    public static final int UNKNOWN = 0;
    public static final int AOSP = 1;
    public static final int GOOGLE = 2;

    private static final String GOOGLE_ROOT_PUBLIC_KEY = "" +
            "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xU" +
            "FmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5j" +
            "lRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y" +
            "//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73X" +
            "pXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYI" +
            "mQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB" +
            "+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7q" +
            "uvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgp" +
            "Zrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7" +
            "gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82" +
            "ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+" +
            "NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==";

    private static final String AOSP_ROOT_PUBLIC_KEY = "" +
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamgu" +
            "D/9/SQ59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpA==";

    public static int verifyCertificateChain(X509Certificate[] certs)
            throws GeneralSecurityException {
        var parent = certs[certs.length - 1];
        var context = AppApplication.getApp().getApplicationContext();
        var stream = context.getResources().openRawResource(R.raw.status);
        var entries = CertificateRevocationStatus.parseStatus(stream);
        for (int i = certs.length - 1; i >= 0; i--) {
            var cert = certs[i];
            cert.checkValidity();
            cert.verify(parent.getPublicKey());
            parent = cert;
            var certStatus = CertificateRevocationStatus.decodeStatus(cert.getSerialNumber(), entries);
            if (certStatus != null) {
                throw new CertificateException("Certificate revocation status is " + certStatus.status);
            }
        }

        var rootPublicKey = certs[certs.length - 1].getPublicKey().getEncoded();
        if (Arrays.equals(rootPublicKey, Base64.decode(GOOGLE_ROOT_PUBLIC_KEY, 0))) {
            return GOOGLE;
        }
        if (Arrays.equals(rootPublicKey, Base64.decode(AOSP_ROOT_PUBLIC_KEY, 0))) {
            return AOSP;
        }
        return UNKNOWN;
    }
}
