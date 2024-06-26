package io.github.vvb2060.keyattestation.attestation;

import android.util.Log;

import androidx.annotation.NonNull;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.math.BigInteger;

import io.github.vvb2060.keyattestation.AppApplication;
import io.github.vvb2060.keyattestation.R;

public record RevocationList(String status, String reason) {
    private static final JSONObject json;

    static {
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

            int i;
            try (InputStream in = AppApplication.app.getResources().openRawResource(R.raw.status)) {
                while ((i = in.read()) > -1) {
                    byteArrayOutputStream.write(i);
                }
            }

            Log.i(AppApplication.TAG, "JSON size: " + byteArrayOutputStream.size());

            json = new JSONObject(byteArrayOutputStream.toString());

        } catch (Throwable t) {
            Log.e(AppApplication.TAG, "getStatus", t);
            throw new RuntimeException(t);
        }
    }


    public static RevocationList get(BigInteger serialNumber) {
        String serialNumberString = serialNumber.toString(16).toLowerCase();

        try {
            JSONObject entries = json.getJSONObject("entries");

            JSONObject revoke = entries.getJSONObject(serialNumberString);

            return new RevocationList(revoke.getString("status"), revoke.getString("reason"));

        } catch (Throwable ignored) {
        }

        return null;
    }

    @NonNull
    @Override
    public String toString() {
        return "status is " + status + ", reason is " + reason;
    }
}
