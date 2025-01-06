package io.github.vvb2060.keyattestation.attestation;

import android.util.Log;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.Map;
import co.nstant.in.cbor.model.Number;
import io.github.vvb2060.keyattestation.AppApplication;

public class ProvisioningInfo {
    private static final String OID = "1.3.6.1.4.1.11129.2.1.30";

    private Integer certsIssued;
    private String manufacturer;

    private ProvisioningInfo(Map map) {
        for (var key : map.getKeys()) {
            switch (((Number) key).getValue().intValue()) {
                case 1 -> certsIssued = CborUtils.getInt(map, key);
                case 3 -> manufacturer = CborUtils.getUnicodeString(map, key);
                default -> Log.w(AppApplication.TAG, "new provisioning info: "
                        + key + " = " + map.get(key));
            }
        }
    }

    public static ProvisioningInfo get(X509Certificate cert) {
        var bytes = cert.getExtensionValue(OID);
        if (bytes == null) return null;
        try {
            var asn1 = Asn1Utils.getAsn1EncodableFromBytes(bytes);
            var cborBytes = Asn1Utils.getByteArrayFromAsn1(asn1);
            var map = (Map) CborUtils.decodeCbor(cborBytes);
            return new ProvisioningInfo(map);
        } catch (CborException | CertificateParsingException e) {
            Log.e(AppApplication.TAG, "decode", e);
            return null;
        }
    }

    public Integer getCertsIssued() {
        return certsIssued;
    }

    public String getManufacturer() {
        return manufacturer;
    }
}
