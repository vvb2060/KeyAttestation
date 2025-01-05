package io.github.vvb2060.keyattestation.repository;

import android.hardware.security.keymint.DeviceInfo;
import android.hardware.security.keymint.RpcHardwareInfo;
import android.util.ArrayMap;

import com.google.common.io.BaseEncoding;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.Map;
import io.github.vvb2060.keyattestation.attestation.CertificateInfo;

public class RemoteProvisioningData extends BaseData {
    private final String rkpHostname;
    private final RpcHardwareInfo hardwareInfo;
    private final java.util.Map<String, String> deviceInfo = new ArrayMap<>();
    private Throwable error;

    public RemoteProvisioningData(String rkpHostname, RpcHardwareInfo hardwareInfo,
                                  DeviceInfo deviceInfoData) throws CborException {
        this.rkpHostname = rkpHostname;
        this.hardwareInfo = hardwareInfo;
        var deviceInfo = (Map) CborDecoder.decode(deviceInfoData.deviceInfo).get(0);
        for (var key : deviceInfo.getKeys()) {
            var value = deviceInfo.get(key);
            String valueString;
            if (value instanceof ByteString byteString) {
                valueString = BaseEncoding.base16().lowerCase().encode(byteString.getBytes());
            } else {
                valueString = value.toString();
            }
            this.deviceInfo.put(key.toString(), valueString);
        }
    }

    @SuppressWarnings("unchecked")
    public void setCerts(Collection<? extends Certificate> data) {
        var infoList = new ArrayList<CertificateInfo>(data.size());
        CertificateInfo.parse((List<X509Certificate>) data, infoList);
        init(infoList);
    }

    public void setError(Throwable error) {
        this.error = error;
        init(List.of());
    }

    public String getRkpHostname() {
        return rkpHostname;
    }

    public RpcHardwareInfo getHardwareInfo() {
        return hardwareInfo;
    }

    public java.util.Map<String, String> getDeviceInfo() {
        return deviceInfo;
    }

    public Throwable getError() {
        return error;
    }
}
