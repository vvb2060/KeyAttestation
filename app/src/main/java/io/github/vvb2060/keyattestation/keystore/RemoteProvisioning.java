package io.github.vvb2060.keyattestation.keystore;

import android.hardware.security.keymint.DeviceInfo;
import android.hardware.security.keymint.IRemotelyProvisionedComponent;
import android.hardware.security.keymint.MacedPublicKey;
import android.hardware.security.keymint.ProtectedData;
import android.hardware.security.keymint.RpcHardwareInfo;
import android.net.Uri;
import android.os.Build;
import android.os.IBinder;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.ServiceSpecificException;
import android.os.SystemProperties;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.RequiresApi;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.HashMap;
import java.util.UUID;

import javax.net.ssl.HttpsURLConnection;

import co.nstant.in.cbor.CborBuilder;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.UnicodeString;
import co.nstant.in.cbor.model.UnsignedInteger;
import io.github.vvb2060.keyattestation.AppApplication;

@RequiresApi(Build.VERSION_CODES.S)
class RemoteProvisioning {
    public static final String PROP_NAME = "remote_provisioning.hostname";
    public static final String HOSTNAME = "remoteprovisioning.googleapis.com";
    private static final String EEK_ED25519_BASE64 = """
            goRDoQEnoFgqpAEBAycgBiFYIJm57t1e5FL2hcZMYtw+YatXSH11NymtdoAy0rPL\
            Y1jZWEAeIghLpLekyNdOAw7+uK8UTKc7b6XN3Np5xitk/pk5r3bngPpmAIUNB5gq\
            rJFcpyUUSQY0dcqKJ3rZ41pJ6wIDhEOhASegWE6lAQECWCDQrsEVyirPc65rzMvR\
            lh1l6LHd10oaN7lDOpfVmd+YCAM4GCAEIVggvoXnRsSjQlpA2TY6phXQLFh+Pdwz\
            AjLS/F4ehyVfcmBYQJvPkOIuS6vRGLEOjl0gJ0uEWP78MpB+cgWDvNeCvvpkeC1U\
            EEvAMb9r6B414vAtzmwvT/L1T6XUg62WovGHWAQ=""";
    private static final String EEK_P256_BASE64 = """
            goRDoQEmoFhNpQECAyYgASFYIPcUituX9MxT79JkEcTjdR9mH6RxDGzP+glGgHSH\
            VPKtIlggXn9b9uzk9hnM/xM3/Q+hyJPbGAZ2xF3m12p3hsMtr49YQC+XjkL7vgct\
            lUeFR5NAsB/Um0ekxESp8qEHhxDHn8sR9L+f6Dvg5zRMFfx7w34zBfTRNDztAgRg\
            ehXgedOK/ySEQ6EBJqBYcaYBAgJYIDVztz+gioCJsSZn6ct8daGvAmH8bmUDkTvT\
            S30UlD5GAzgYIAEhWCDgQc8vDzQPHDMsQbDP1wwwVTXSHmpHE0su0UiWfiScaCJY\
            IB/ORcX7YbqBIfnlBZubOQ52hoZHuB4vRfHOr9o/gGjbWECMs7p+ID4ysGjfYNEd\
            ffCsOI5RvP9s4Wc7Snm8Vnizmdh8igfY2rW1f3H02GvfMyc0e2XRKuuGmZirOrSA\
            qr1Q""";

    private static RemoteProvisioning instance_default;
    private static RemoteProvisioning instance_strongbox;

    private final String requestId = UUID.randomUUID().toString();
    private final IRemotelyProvisionedComponent binder;
    private byte[] deviceInfoData;

    private static class EekResponse {
        private final byte[] challenge;
        private final HashMap<Integer, byte[]> curveToGeek = new HashMap<>();

        EekResponse(DataItem response) throws CborException {
            var respItems = ((Array) response).getDataItems();
            var allEekChains = ((Array) respItems.get(0)).getDataItems();
            for (var entry : allEekChains) {
                var curveAndEekChain = ((Array) entry).getDataItems();
                var curve = (UnsignedInteger) curveAndEekChain.get(0);
                var geek = encodeCbor(curveAndEekChain.get(1));
                curveToGeek.put(curve.getValue().intValue(), geek);
            }
            challenge = ((ByteString) respItems.get(1)).getBytes();
        }

        EekResponse() {
            challenge = Instant.now().toString().getBytes();
            curveToGeek.put(RpcHardwareInfo.CURVE_25519, Base64.decode(EEK_ED25519_BASE64, 0));
            curveToGeek.put(RpcHardwareInfo.CURVE_P256, Base64.decode(EEK_P256_BASE64, 0));
        }

        byte[] getEekChain(int curve) {
            return curveToGeek.get(curve);
        }

        byte[] getChallenge() {
            return challenge;
        }
    }

    public static RemoteProvisioning getInstance(boolean useStrongBox) {
        if (useStrongBox) {
            if (instance_strongbox == null) {
                instance_strongbox = new RemoteProvisioning(true);
            }
            return instance_strongbox;
        } else {
            if (instance_default == null) {
                instance_default = new RemoteProvisioning(false);
            }
            return instance_default;
        }
    }

    private RemoteProvisioning(boolean useStrongBox) {
        var instanceName = useStrongBox ? "strongbox" : "default";
        var serviceName = IRemotelyProvisionedComponent.DESCRIPTOR + "/" + instanceName;
        IBinder iBinder = null;
        try {
            iBinder = ServiceManager.waitForDeclaredService(serviceName);
        } catch (SecurityException | NoSuchMethodError ignored) {
        }
        binder = IRemotelyProvisionedComponent.Stub.asInterface(iBinder);
    }

    public boolean isSupported() {
        return binder != null && binder.asBinder().pingBinder();
    }

    public RpcHardwareInfo getHardwareInfo() throws RemoteException {
        return binder.getHardwareInfo();
    }

    public byte[] getDeviceInfo() {
        return deviceInfoData;
    }

    public byte[] check() throws RuntimeException {
        try {
            var eekResponse = fetchEek();
            var csr = generateCsr(eekResponse);
            return signCertificates(csr, eekResponse.getChallenge());
        } catch (SocketTimeoutException | UnknownHostException e) {
            Log.e(AppApplication.TAG, Log.getStackTraceString(e));
            throw new RuntimeException("No network: " + e.getMessage());
        } catch (ServiceSpecificException e) {
            Log.e(AppApplication.TAG, Log.getStackTraceString(e));
            throw new RuntimeException("Error getting CSR: " + e);
        } catch (IOException | CborException | RemoteException e) {
            Log.e(AppApplication.TAG, Log.getStackTraceString(e));
            throw new RuntimeException("Error checking device registration: " + e);
        }
    }

    public void localCsr() throws RuntimeException {
        try {
            var eekResponse = new EekResponse();
            generateCsr(eekResponse);
        } catch (ServiceSpecificException e) {
            Log.e(AppApplication.TAG, Log.getStackTraceString(e));
            throw new RuntimeException("Error getting CSR: " + e);
        } catch (CborException | RemoteException e) {
            Log.e(AppApplication.TAG, Log.getStackTraceString(e));
            throw new RuntimeException("Error checking device registration: " + e);
        }
    }

    private static Uri.Builder getBaseUri() {
        return new Uri.Builder()
                .scheme("https")
                .authority(SystemProperties.get(PROP_NAME, HOSTNAME))
                .appendPath("v1");
    }

    private EekResponse fetchEek() throws IOException, CborException {
        var uri = getBaseUri().appendEncodedPath(":fetchEekChain").build();
        var input = encodeCbor(new CborBuilder()
                .addMap()
                .put("fingerprint", Build.FINGERPRINT)
                .put(new UnicodeString("id"), new UnsignedInteger(0))
                .end()
                .build()
                .get(0));
        return new EekResponse(httpPost(uri, input));
    }

    private byte[] signCertificates(byte[] csr, byte[] challenge)
            throws IOException, CborException {
        var encoded = Base64.encodeToString(challenge, Base64.URL_SAFE | Base64.NO_WRAP);
        var uri = getBaseUri()
                .appendEncodedPath(":signCertificates")
                .appendQueryParameter("challenge", encoded)
                .build();
        var response = httpPost(uri, csr);
        var dataItems = ((Array) response).getDataItems();
        var shared = ((ByteString) dataItems.get(0)).getBytes();
        var leafItem = ((Array) dataItems.get(1)).getDataItems().get(0);
        var leaf = ((ByteString) leafItem).getBytes();
        var full = new byte[leaf.length + shared.length];
        System.arraycopy(leaf, 0, full, 0, leaf.length);
        System.arraycopy(shared, 0, full, leaf.length, shared.length);
        return full;
    }

    private DataItem httpPost(Uri uri, byte[] input) throws IOException, CborException {
        uri = uri.buildUpon().appendQueryParameter("requestId", requestId).build();
        var con = (HttpsURLConnection) new URL(uri.toString()).openConnection();
        con.setRequestMethod("POST");
        con.setConnectTimeout(2_000);
        con.setReadTimeout(20_000);
        con.setDoOutput(true);
        con.setFixedLengthStreamingMode(input.length);

        con.connect();
        try (var os = con.getOutputStream()) {
            os.write(input, 0, input.length);
        }

        var code = con.getResponseCode();
        var body = new ByteArrayOutputStream(8192);
        try (var in = code >= 400 ? con.getErrorStream() : con.getInputStream()) {
            var buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer, 0, buffer.length)) != -1) {
                body.write(buffer, 0, read);
            }
        }
        con.disconnect();

        if (code == 200) {
            return decodeCbor(body.toByteArray());
        } else if (code == 444) {
            throw new RuntimeException("Device not registered.");
        } else {
            throw new RuntimeException(body.toString());
        }
    }

    private byte[] generateCsr(EekResponse eekResponse)
            throws RemoteException, CborException {
        var unverifiedDeviceInfo = new Map().put(
                new UnicodeString("fingerprint"), new UnicodeString(Build.FINGERPRINT));
        var hwInfo = binder.getHardwareInfo();
        var keysToSign = new MacedPublicKey[]{new MacedPublicKey()};
        binder.generateEcdsaP256KeyPair(false, keysToSign[0]);
        if (hwInfo.versionNumber < 3) {
            var deviceInfo = new DeviceInfo();
            var protectedData = new ProtectedData();
            var geekChain = eekResponse.getEekChain(hwInfo.supportedEekCurve);
            var csrTag = binder.generateCertificateRequest(false, keysToSign, geekChain,
                    eekResponse.getChallenge(), deviceInfo, protectedData);
            var mac0Message = buildMac0MessageForV1Csr(keysToSign[0], csrTag);
            deviceInfoData = deviceInfo.deviceInfo;
            return encodeCbor(new CborBuilder()
                    .addArray()
                    .addArray()
                    .add(decodeCbor(deviceInfo.deviceInfo))
                    .add(unverifiedDeviceInfo)
                    .end()
                    .add(eekResponse.getChallenge())
                    .add(decodeCbor(protectedData.protectedData))
                    .add(mac0Message)
                    .end()
                    .build().get(0));
        } else {
            var csrBytes = binder.generateCertificateRequestV2(keysToSign,
                    eekResponse.getChallenge());
            var array = (Array) decodeCbor(csrBytes);
            var deviceInfo = extractDeviceInfoFromV3Csr(array);
            deviceInfoData = encodeCbor(deviceInfo);
            return encodeCbor(array.add(unverifiedDeviceInfo));
        }
    }

    private static Array buildMac0MessageForV1Csr(MacedPublicKey keyToSign, byte[] csrTag)
            throws CborException {
        var macedPayload = ((Array) decodeCbor(keyToSign.macedKey)).getDataItems().get(2);
        var macedCoseKey = (Map) decodeCbor(((ByteString) macedPayload).getBytes());
        var macedKeys = encodeCbor(new Array().add(macedCoseKey));
        var protectedHeaders = new Map().put(
                new UnsignedInteger(1),
                new UnsignedInteger(5));
        return new Array()
                .add(new ByteString(encodeCbor(protectedHeaders)))
                .add(new Map())
                .add(new ByteString(macedKeys))
                .add(new ByteString(csrTag));
    }

    private static Map extractDeviceInfoFromV3Csr(Array csr) throws CborException {
        var signedMap = (Array) csr.getDataItems().get(3);
        var encodedData = (ByteString) signedMap.getDataItems().get(2);
        var decodedPayload = (Array) decodeCbor(encodedData.getBytes());
        var encodedCsrPayload = (ByteString) decodedPayload.getDataItems().get(1);
        var csrPayload = (Array) decodeCbor(encodedCsrPayload.getBytes());
        return (Map) csrPayload.getDataItems().get(2);
    }

    private static DataItem decodeCbor(byte[] encodedBytes) throws CborException {
        return CborDecoder.decode(encodedBytes).get(0);
    }

    private static byte[] encodeCbor(DataItem dataItem) throws CborException {
        var outputStream = new ByteArrayOutputStream(1024);
        new CborEncoder(outputStream).encode(dataItem);
        return outputStream.toByteArray();
    }
}
