package com.samsung.android.security.keystore;

public class DeviceIdAttestationException extends Exception {
    public DeviceIdAttestationException(String detailMessage) {
        super(detailMessage);
    }

    public DeviceIdAttestationException(String message, Throwable cause) {
        super(message, cause);
    }
}
