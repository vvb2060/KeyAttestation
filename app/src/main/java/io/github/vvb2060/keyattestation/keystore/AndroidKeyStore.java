package io.github.vvb2060.keyattestation.keystore;

import android.annotation.SuppressLint;
import android.app.ActivityThread;
import android.app.Application;
import android.app.Instrumentation;
import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.hardware.security.keymint.DeviceInfo;
import android.hardware.security.keymint.RpcHardwareInfo;
import android.os.Binder;
import android.os.Build;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.os.RemoteException;
import android.os.SystemProperties;
import android.security.keystore.AttestationUtils;
import android.security.keystore.DeviceIdAttestationException;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyGenParameterSpec_rename;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.system.Os;
import android.util.Log;

import com.samsung.android.security.keystore.AttestParameterSpec;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Date;
import java.util.Objects;

import javax.security.auth.x500.X500Principal;

import io.github.vvb2060.keyattestation.AppApplication;
import io.github.vvb2060.keyattestation.BuildConfig;
import rikka.shizuku.ShizukuApiConstants;

public class AndroidKeyStore extends IAndroidKeyStore.Stub {
    private final KeyStore keyStore;
    private final KeyPairGenerator keyPairGenerator;
    private int clientUid = -1;

    public AndroidKeyStore() throws Exception {
        if (Os.geteuid() < Process.FIRST_APPLICATION_UID) {
            fixEnv();
            var pm = ActivityThread.currentApplication().getPackageManager();
            clientUid = pm.getApplicationInfo(BuildConfig.APPLICATION_ID, 0).uid;
        }
        keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
    }

    private static void fixEnv() throws Exception {
        var packageName = "com.android.shell";
        switch (Os.geteuid()) {
            case Process.ROOT_UID:
                if (Os.gettid() == Os.getpid()) {
                    Os.seteuid(Process.SYSTEM_UID);
                } else {
                    throw new RuntimeException("tid!=pid");
                }
            case Process.SYSTEM_UID:
                packageName = "android";
            case Process.SHELL_UID: {
                break;
            }
            default:
                throw new RuntimeException("unexpected uid");
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            ActivityThread.initializeMainlineModules();
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            android.security.keystore2.AndroidKeyStoreProvider.install();
        } else {
            android.security.keystore.AndroidKeyStoreProvider.install();
        }

        var activityThread = ActivityThread.systemMain();
        Context systemContext = activityThread.getSystemContext();
        var flags = Context.CONTEXT_INCLUDE_CODE | Context.CONTEXT_IGNORE_SECURITY;
        var context = systemContext.createPackageContext(packageName, flags);
        var mPackageInfo = context.getClass().getDeclaredField("mPackageInfo");
        mPackageInfo.setAccessible(true);
        var loadedApk = mPackageInfo.get(context);
        var makeApplication = loadedApk.getClass().getDeclaredMethod("makeApplication",
                boolean.class, Instrumentation.class);
        var application = (Application) makeApplication.invoke(loadedApk, true, null);
        ContextHook.hook(application);
        var mInitialApplication = ActivityThread.class.getDeclaredField("mInitialApplication");
        mInitialApplication.setAccessible(true);
        mInitialApplication.set(activityThread, application);
    }

    @Override
    @SuppressLint("RestrictedApi")
    public boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
        var callingUid = Binder.getCallingUid();
        if (callingUid != clientUid
                && callingUid != Process.SHELL_UID
                && callingUid != Process.ROOT_UID
                && callingUid != Process.SYSTEM_UID) {
            return false;
        }
        if (code == ShizukuApiConstants.USER_SERVICE_TRANSACTION_destroy) {
            System.exit(0);
        }
        return super.onTransact(code, data, reply, flags);
    }

    @Override
    public byte[] getCertificateChain(String alias) {
        try {
            var chain = keyStore.getCertificateChain(alias);
            if (chain == null) {
                return null;
            }
            var buf = new ByteArrayOutputStream(8192);
            for (var cert : chain) {
                buf.write(cert.getEncoded());
            }
            return buf.toByteArray();
        } catch (Exception e) {
            Log.e(AppApplication.TAG, "getCertificateChain", e);
            throw new IllegalStateException(e.getMessage());
        }
    }

    @Override
    public boolean containsAlias(String alias) {
        try {
            return keyStore.containsAlias(alias);
        } catch (KeyStoreException e) {
            Log.e(AppApplication.TAG, "containsAlias", e);
            throw new IllegalStateException(e.getMessage());
        }
    }

    @Override
    public void deleteAllEntry() {
        try {
            var aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                var alias = aliases.nextElement();
                keyStore.deleteEntry(alias);
            }
        } catch (KeyStoreException e) {
            Log.e(AppApplication.TAG, "deleteAllEntry", e);
            throw new IllegalStateException(e.getMessage());
        }
    }

    @Override
    public void importKeyBox(String alias, boolean useStrongBox, ParcelFileDescriptor pfd) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            throw new IllegalStateException();
        }
        try (var in = new ParcelFileDescriptor.AutoCloseInputStream(pfd)) {
            var key = KeyBoxXmlParser.getInstance().parse(in);
            var builder = new KeyProtection.Builder(KeyProperties.PURPOSE_ATTEST_KEY)
                    .setDigests(KeyProperties.DIGEST_SHA256);
            if (useStrongBox) {
                builder.setIsStrongBoxBacked(true);
            }
            keyStore.setEntry(alias, key, builder.build());
            if (keyStore.getCertificate(alias) == null) {
                throw new IllegalStateException("import failed");
            }
        } catch (IOException | KeyStoreException e) {
            Log.e(AppApplication.TAG, "importKeyBox", e);
            throw new IllegalStateException(e.getMessage());
        }
    }

    private static int[] flagsToArray(int idFlags) {
        int i = 0;
        var array = new int[3];
        if ((idFlags & DevicePolicyManager.ID_TYPE_SERIAL) != 0) {
            array[i++] = 1;
        }
        if ((idFlags & DevicePolicyManager.ID_TYPE_IMEI) != 0) {
            array[i++] = 2;
        }
        if ((idFlags & DevicePolicyManager.ID_TYPE_MEID) != 0) {
            array[i++] = 3;
        }
        return Arrays.copyOf(array, i);
    }

    private static Object genParameter(String alias,
                                       String attestKeyAlias,
                                       boolean useStrongBox,
                                       boolean includeProps,
                                       boolean uniqueIdIncluded,
                                       int[] attestationIds) {
        var now = new Date();
        boolean attestKey = Objects.equals(alias, attestKeyAlias);
        var purposes = attestKey ? KeyProperties.PURPOSE_ATTEST_KEY : KeyProperties.PURPOSE_SIGN;

        var builder = new KeyGenParameterSpec_rename.Builder(alias, purposes)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setCertificateNotBefore(now)
                .setAttestationChallenge(now.toString().getBytes());
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && useStrongBox) {
            builder.setIsStrongBoxBacked(true);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (includeProps) {
                builder.setDevicePropertiesAttestationIncluded(true);
            }
            if (attestationIds != null) {
                builder.setAttestationIds(attestationIds);
            }
            if (attestKey) {
                builder.setCertificateSubject(new X500Principal("CN=App Attest Key"));
            } else {
                builder.setAttestKeyAlias(attestKeyAlias);
            }
        }
        if (uniqueIdIncluded) {
            builder.setUniqueIdIncluded(true);
        }
        return builder.build();
    }

    private static AttestParameterSpec genSakParameter(KeyGenParameterSpec params) {
        var alias = params.getKeystoreAlias();
        var challenge = params.getAttestationChallenge();
        var packageName = ActivityThread.currentApplication().getPackageName();
        var builder = new AttestParameterSpec.Builder(alias, challenge)
                .setAlgorithm(KeyProperties.KEY_ALGORITHM_EC)
                .setKeyGenParameterSpec(params)
                .setVerifiableIntegrity(true)
                .setDeviceAttestation(true)
                .setPackageName(packageName);
        return builder.build();
    }

    @Override
    public byte[] generateKeyPair(String alias,
                                  String attestKeyAlias,
                                  boolean useStrongBox,
                                  boolean includeProps,
                                  boolean uniqueIdIncluded,
                                  int idFlags,
                                  boolean useSak) {
        var params = (KeyGenParameterSpec) genParameter(alias, attestKeyAlias, useStrongBox,
                includeProps, uniqueIdIncluded, flagsToArray(idFlags));
        try {
            keyPairGenerator.initialize(params);
            keyPairGenerator.generateKeyPair();
            if (useSak) {
                var utils = new com.samsung.android.security.keystore.AttestationUtils();
                var spec = genSakParameter(params);
                Iterable<byte[]> certChain;
                if (spec.isDeviceAttestation()) {
                    certChain = utils.attestDevice(spec);
                } else {
                    certChain = utils.attestKey(spec);
                }
                utils.storeCertificateChain(alias, certChain);
            }
            return null;
        } catch (Exception exception) {
            Log.e(AppApplication.TAG, "generateKeyPair", exception);
            var buf = new ByteArrayOutputStream(2048);
            try (var out = new ObjectOutputStream(buf)) {
                out.writeObject(exception);
            } catch (IOException e) {
                throw new IllegalStateException(e.getMessage());
            }
            return buf.toByteArray();
        }
    }

    @Override
    public byte[] attestDeviceIds(int idFlags) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
                || Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            throw new IllegalStateException();
        }
        var context = ActivityThread.currentApplication();
        var attestationIds = flagsToArray(idFlags);
        var challenge = new Date().toString().getBytes();
        try {
            var chain = AttestationUtils.attestDeviceIds(context, attestationIds, challenge);
            var buf = new ByteArrayOutputStream(8192);
            buf.write(1);
            for (var cert : chain) {
                buf.write(cert.getEncoded());
            }
            return buf.toByteArray();
        } catch (DeviceIdAttestationException exception) {
            Log.e(AppApplication.TAG, "attestDeviceIds", exception);
            var buf = new ByteArrayOutputStream(2048);
            buf.write(0);
            try (var out = new ObjectOutputStream(buf)) {
                out.writeObject(exception);
            } catch (IOException e) {
                throw new IllegalStateException(e.getMessage());
            }
            return buf.toByteArray();
        } catch (CertificateEncodingException | IOException e) {
            throw new IllegalStateException(e.getMessage());
        }
    }

    @Override
    public void setRkpHostname(String hostname) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            throw new IllegalStateException();
        }
        SystemProperties.set(RemoteProvisioning.PROP_NAME, hostname);
    }

    @Override
    public String getRkpHostname() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            throw new IllegalStateException();
        }
        return SystemProperties.get(RemoteProvisioning.PROP_NAME);
    }

    @Override
    public boolean canRemoteProvisioning(boolean useStrongBox) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            throw new IllegalStateException();
        }
        var rkp = RemoteProvisioning.getInstance(useStrongBox);
        return rkp.isSupported();
    }

    @Override
    public RpcHardwareInfo getHardwareInfo(boolean useStrongBox, DeviceInfo deviceInfo) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            throw new IllegalStateException();
        }
        try {
            var rkp = RemoteProvisioning.getInstance(useStrongBox);
            rkp.localCsr();
            deviceInfo.deviceInfo = rkp.getDeviceInfo();
            return rkp.getHardwareInfo();
        } catch (Exception e) {
            Log.e(AppApplication.TAG, "getHardwareInfo", e);
            throw new IllegalStateException(e.getMessage());
        }
    }

    @Override
    public byte[] checkRemoteProvisioning(boolean useStrongBox) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
            throw new IllegalStateException();
        }
        try {
            var rkp = RemoteProvisioning.getInstance(useStrongBox);
            return rkp.check();
        } catch (Exception e) {
            Log.e(AppApplication.TAG, "checkRemoteProvisioning", e);
            throw new IllegalStateException(e.getMessage());
        }
    }
}
