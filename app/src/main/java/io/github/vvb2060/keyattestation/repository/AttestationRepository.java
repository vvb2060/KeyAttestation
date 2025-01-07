package io.github.vvb2060.keyattestation.repository;

import static android.security.KeyStoreException.ERROR_ATTESTATION_KEYS_UNAVAILABLE;
import static android.security.KeyStoreException.ERROR_ID_ATTESTATION_FAILURE;
import static android.security.KeyStoreException.ERROR_KEYMINT_FAILURE;
import static io.github.vvb2060.keyattestation.lang.AttestationException.*;

import android.annotation.SuppressLint;
import android.hardware.security.keymint.DeviceInfo;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.security.KeyStoreException;
import android.security.keystore.DeviceIdAttestationException;
import android.security.keystore.StrongBoxUnavailableException;
import android.util.Log;

import androidx.annotation.RequiresApi;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.security.ProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import io.github.vvb2060.keyattestation.AppApplication;
import io.github.vvb2060.keyattestation.keystore.AndroidKeyStore;
import io.github.vvb2060.keyattestation.keystore.IAndroidKeyStore;
import io.github.vvb2060.keyattestation.keystore.KeyStoreManager;
import io.github.vvb2060.keyattestation.lang.AttestationException;
import io.github.vvb2060.keyattestation.util.Resource;

public class AttestationRepository {
    private final AndroidKeyStore localKeyStore;
    private final CertificateFactory factory;
    private final List<X509Certificate> currentCerts;
    private IAndroidKeyStore keyStore;

    public AttestationRepository() throws Exception {
        localKeyStore = new AndroidKeyStore();
        factory = CertificateFactory.getInstance("X.509");
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
    private void generateCertificates(InputStream in) throws CertificateException {
        var list = (List<X509Certificate>) factory.generateCertificates(in);
        if (list.isEmpty()) {
            throw new CertificateException("No certificate");
        }
        currentCerts.addAll(list);
    }

    @SuppressWarnings("unchecked")
    private void generateCertPath(InputStream in) throws CertificateException {
        var list = (List<X509Certificate>) factory.generateCertPath(in).getCertificates();
        if (list.isEmpty()) {
            throw new CertificateException("No certificate");
        }
        currentCerts.addAll(list);
    }

    private void generateKeyPair(String alias, String attestKeyAlias,
                                 boolean useStrongBox, boolean includeProps,
                                 boolean uniqueIdIncluded, int idFlags,
                                 boolean useSak) throws Exception {
        var data = keyStore.generateKeyPair(alias, attestKeyAlias, useStrongBox,
                includeProps, uniqueIdIncluded, idFlags, useSak);
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
            generateCertificates(in);
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

    private void getCertChain(String alias) throws RemoteException, CertificateException {
        var certChain = keyStore.getCertificateChain(alias);
        if (certChain == null) {
            throw new ProviderException("Unable to get certificate chain");
        }
        generateCertificates(new ByteArrayInputStream(certChain));
    }

    private void doAttestation(boolean useAttestKey, boolean useStrongBox,
                               boolean includeProps, boolean uniqueIdIncluded,
                               int idFlags, boolean useSak) throws AttestationException {
        var alias = useStrongBox ? AppApplication.TAG + "_strongbox" : AppApplication.TAG;
        var attestKeyAlias = useAttestKey ? alias + "_persistent" : null;
        try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S && idFlags != 0) {
                attestDeviceIds(idFlags);
                return;
            }

            if (useAttestKey && !keyStore.containsAlias(attestKeyAlias)) {
                generateKeyPair(attestKeyAlias, attestKeyAlias, useStrongBox,
                        includeProps, uniqueIdIncluded, idFlags, false);
            }
            generateKeyPair(alias, attestKeyAlias, useStrongBox,
                    includeProps, uniqueIdIncluded, idFlags, useSak);

            getCertChain(alias);
            if (useAttestKey) {
                getCertChain(attestKeyAlias);
            }
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

    public Resource<AttestationData> attest(boolean reset, boolean useAttestKey,
                                            boolean useStrongBox, boolean includeProps,
                                            boolean uniqueIdIncluded, int idFlags, boolean useSak) {
        currentCerts.clear();
        try {
            if (reset) keyStore.deleteAllEntry();
            doAttestation(useAttestKey, useStrongBox, includeProps,
                    uniqueIdIncluded, idFlags, useSak);
            return Resource.Companion.success(AttestationData.parseCertificateChain(currentCerts));
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

    public Resource<AttestationData> loadCerts(ParcelFileDescriptor pfd) {
        currentCerts.clear();
        try {
            AttestationData data;
            try (var in = new ParcelFileDescriptor.AutoCloseInputStream(pfd);
                 var channel = in.getChannel()) {
                try {
                    generateCertificates(in);
                    data = AttestationData.parseCertificateChain(currentCerts);
                } catch (CertificateException e) {
                    channel.position(0);
                    generateCertPath(in);
                    data = AttestationData.parseCertificateChain(currentCerts);
                }
            }
            return Resource.Companion.success(data);
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

    public void saveCerts(OutputStream out) throws Exception {
        var certPath = factory.generateCertPath(currentCerts);
        out.write(certPath.getEncoded("PKCS7"));
    }

    public void importKeyBox(boolean useStrongBox, ParcelFileDescriptor pfd) throws Exception {
        var base = useStrongBox ? AppApplication.TAG + "_strongbox" : AppApplication.TAG;
        var alias = base + "_persistent";
        keyStore.importKeyBox(alias, useStrongBox, pfd);
    }

    public boolean canRkp(boolean useStrongBox) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            return false;
        }
        try {
            return keyStore.canRemoteProvisioning(useStrongBox);
        } catch (RemoteException e) {
            return false;
        }
    }

    public Resource<RemoteProvisioningData> checkRkp(boolean useStrongBox) {
        currentCerts.clear();
        try {
            var name = Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE
                    ? keyStore.getRkpHostname() : null;
            var deviceInfo = new DeviceInfo();
            var hw = keyStore.getHardwareInfo(useStrongBox, deviceInfo);
            var info = new RemoteProvisioningData(name, hw, deviceInfo);
            try {
                var data = keyStore.checkRemoteProvisioning(useStrongBox);
                info.setCerts(factory.generateCertificates(new ByteArrayInputStream(data)));
            } catch (IllegalStateException e) {
                info.setError(e);
            }
            return Resource.Companion.success(info);
        } catch (Exception e) {
            var cause = e instanceof AttestationException ? e.getCause() : e;
            Log.w(AppApplication.TAG, "Check RKP error.", cause);

            if (e instanceof IllegalStateException) {
                return Resource.Companion.error(new AttestationException(CODE_RKP, e), null);
            } else {
                return Resource.Companion.error(new AttestationException(CODE_UNKNOWN, e), null);
            }
        }
    }

    public void setHostname(String hostname) {
        if (hostname == null) return;
        try {
            keyStore.setRkpHostname(hostname);
        } catch (RemoteException e) {
            Log.w(AppApplication.TAG, "Set RKP hostname error.", e);
        }
    }
}
