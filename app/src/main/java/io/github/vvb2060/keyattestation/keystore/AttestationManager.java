package io.github.vvb2060.keyattestation.keystore;

import static android.security.KeyStoreException.ERROR_ATTESTATION_KEYS_UNAVAILABLE;
import static android.security.KeyStoreException.ERROR_ID_ATTESTATION_FAILURE;
import static android.security.KeyStoreException.ERROR_KEYMINT_FAILURE;
import static io.github.vvb2060.keyattestation.lang.AttestationException.*;

import android.annotation.SuppressLint;
import android.content.ContentResolver;
import android.net.Uri;
import android.os.Build;
import android.security.KeyStoreException;
import android.security.keystore.DeviceIdAttestationException;
import android.security.keystore.StrongBoxUnavailableException;
import android.util.Log;

import androidx.annotation.RequiresApi;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.ProviderException;
import java.security.cert.CertPath;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import io.github.vvb2060.keyattestation.AppApplication;
import io.github.vvb2060.keyattestation.attestation.AttestationResult;
import io.github.vvb2060.keyattestation.attestation.CertificateInfo;
import io.github.vvb2060.keyattestation.lang.AttestationException;
import io.github.vvb2060.keyattestation.util.Resource;

public final class AttestationManager {
    private final AndroidKeyStore localKeyStore;
    private final CertificateFactory certificateFactory;
    private final List<X509Certificate> currentCerts;
    private IAndroidKeyStore keyStore;

    public AttestationManager() throws Exception {
        localKeyStore = new AndroidKeyStore();
        certificateFactory = CertificateFactory.getInstance("X.509");
        currentCerts = new ArrayList<>();
        keyStore = localKeyStore;
    }

    public void useRemoteKeyStore(boolean useRemote) {
        if (useRemote) {
            keyStore = KeyStoreManager.getRemoteKeyStore();
        } else {
            keyStore = localKeyStore;
        }
    }

    public boolean hasCertificates() {
        return !currentCerts.isEmpty();
    }

    @SuppressWarnings("unchecked")
    private void addToCurrentCerts(ByteArrayInputStream in) throws CertificateException {
        var list = (List<X509Certificate>) certificateFactory.generateCertificates(in);
        currentCerts.addAll(list);
    }

    private void generateKeyPair(String alias, String attestKeyAlias,
                                 boolean useStrongBox, boolean includeProps,
                                 boolean uniqueIdIncluded, int idFlags) throws Exception {
        var data = keyStore.generateKeyPair(alias, attestKeyAlias, useStrongBox,
                includeProps, uniqueIdIncluded, idFlags);
        if (data != null) {
            try (var it = new ObjectInputStream((new ByteArrayInputStream(data)))) {
                throw (Exception) it.readObject();
            }
        }
    }

    private void attestDeviceIds(int idFlags) throws Exception {
        var data = keyStore.attestDeviceIds(idFlags);
        var in = new ByteArrayInputStream(data);
        if (in.read() == 1) {
            addToCurrentCerts(in);
        } else {
            try (var it = new ObjectInputStream((in))) {
                var exception = (Exception) it.readObject();
                throw new ProviderException(exception);
            }
        }
    }

    @SuppressLint("SwitchIntDef")
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private static AttestationException toAttestationException(KeyStoreException exception,
                                                               Exception e) {
        int code = exception.getNumericErrorCode();
        if (code == ERROR_ID_ATTESTATION_FAILURE) {
            return new AttestationException(CODE_DEVICEIDS_UNAVAILABLE, e);
        }
        if (code >= ERROR_ATTESTATION_KEYS_UNAVAILABLE) {
            if (exception.isTransientFailure()) {
                return new AttestationException(CODE_OUT_OF_KEYS_TRANSIENT, e);
            } else {
                return new AttestationException(CODE_OUT_OF_KEYS, e);
            }
        }
        if (code == ERROR_KEYMINT_FAILURE) {
            if (exception.toString().contains("ATTESTATION_KEYS_NOT_PROVISIONED")) {
                return new AttestationException(CODE_KEYS_NOT_PROVISIONED, e);
            }
        }
        if (exception.isTransientFailure()) {
            return new AttestationException(CODE_UNAVAILABLE_TRANSIENT, e);
        } else {
            return new AttestationException(CODE_UNAVAILABLE, e);
        }
    }

    private AttestationResult doAttestation(boolean useAttestKey, boolean useStrongBox,
                                            boolean includeProps, boolean uniqueIdIncluded,
                                            int idFlags) throws AttestationException {
        var alias = useStrongBox ? AppApplication.TAG + "_strongbox" : AppApplication.TAG;
        var attestKeyAlias = useAttestKey ? alias + "_persistent" : null;
        try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S && idFlags != 0) {
                attestDeviceIds(idFlags);
                return CertificateInfo.parseCertificateChain(currentCerts);
            }

            if (useAttestKey && !keyStore.containsAlias(attestKeyAlias)) {
                generateKeyPair(attestKeyAlias, attestKeyAlias, useStrongBox,
                        includeProps, uniqueIdIncluded, idFlags);
            }
            generateKeyPair(alias, attestKeyAlias, useStrongBox,
                    includeProps, uniqueIdIncluded, idFlags);

            var certChain = keyStore.getCertificateChain(alias);
            if (certChain == null)
                throw new CertificateException("Unable to get certificate chain");
            addToCurrentCerts(new ByteArrayInputStream(certChain));
            if (useAttestKey) {
                var persistChain = keyStore.getCertificateChain(attestKeyAlias);
                if (persistChain == null)
                    throw new CertificateException("Unable to get certificate chain");
                addToCurrentCerts(new ByteArrayInputStream(persistChain));
            }
            return CertificateInfo.parseCertificateChain(currentCerts);
        } catch (ProviderException e) {
            var cause = e.getCause();
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
                    && e instanceof StrongBoxUnavailableException) {
                throw new AttestationException(CODE_STRONGBOX_UNAVAILABLE, e);
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
                    && cause instanceof KeyStoreException keyStoreException) {
                throw toAttestationException(keyStoreException, e);
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                    && cause instanceof DeviceIdAttestationException) {
                throw new AttestationException(CODE_DEVICEIDS_UNAVAILABLE, e);
            } else if (cause != null && cause.toString().contains("device ids")) {
                throw new AttestationException(CODE_DEVICEIDS_UNAVAILABLE, e);
            } else {
                throw new AttestationException(CODE_UNAVAILABLE, e);
            }
        } catch (Exception e) {
            throw new AttestationException(CODE_UNKNOWN, e);
        }
    }

    public Resource<AttestationResult> attest(boolean reset, boolean useAttestKey,
                                              boolean useStrongBox, boolean includeProps,
                                              boolean uniqueIdIncluded, int idFlags) {
        currentCerts.clear();
        try {
            if (reset) keyStore.deleteAllEntry();
            var attestationResult = doAttestation(useAttestKey, useStrongBox, includeProps,
                    uniqueIdIncluded, idFlags);
            return Resource.Companion.success(attestationResult);
        } catch (Exception e) {
            var cause = e instanceof AttestationException ? e.getCause() : e;
            Log.w(AppApplication.TAG, "Do attestation error.", cause);

            if (e instanceof AttestationException) {
                return Resource.Companion.error(e, null);
            } else {
                return Resource.Companion.error(new AttestationException(CODE_UNKNOWN, e), null);
            }
        }
    }

    public Resource<AttestationResult> loadCerts(ContentResolver cr, Uri uri) {
        currentCerts.clear();
        try {
            CertPath certPath;
            try {
                try (var it = cr.openInputStream(uri)) {
                    certPath = certificateFactory.generateCertPath(it, "PKCS7");
                }
            } catch (CertificateException e) {
                try (var it = cr.openInputStream(uri)) {
                    certPath = certificateFactory.generateCertPath(it);
                }
            }
            return Resource.Companion.success(CertificateInfo.parseCertificateChain(certPath));
        } catch (Exception e) {
            var cause = e instanceof AttestationException ? e.getCause() : e;
            Log.w(AppApplication.TAG, "Load attestation error.", cause);

            if (e instanceof AttestationException) {
                return Resource.Companion.error(e, null);
            } else if (e instanceof CertificateException) {
                return Resource.Companion.error(new AttestationException(CODE_CANT_PARSE_CERT, e), null);
            } else {
                return Resource.Companion.error(new AttestationException(CODE_UNKNOWN, e), null);
            }
        }
    }

    public void saveCerts(ContentResolver cr, Uri uri) throws Exception {
        var certPath = certificateFactory.generateCertPath(currentCerts);
        try (var out = cr.openOutputStream(uri)) {
            if (out == null) throw new IOException("openOutputStream failed: " + uri);
            out.write(certPath.getEncoded("PKCS7"));
        }
    }

    public void importKeyBox(boolean useStrongBox, ContentResolver cr, Uri uri) throws Exception {
        var base = useStrongBox ? AppApplication.TAG + "_strongbox" : AppApplication.TAG;
        var alias = base + "_persistent";
        try (var pfd = cr.openFileDescriptor(uri, "r")) {
            keyStore.importKeyBox(alias, useStrongBox, pfd);
        }
    }
}
