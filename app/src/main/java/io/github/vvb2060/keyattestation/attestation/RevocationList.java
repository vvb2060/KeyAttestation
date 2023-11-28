package io.github.vvb2060.keyattestation.attestation;

import android.os.Build;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

import io.github.vvb2060.keyattestation.AppApplication;
import io.github.vvb2060.keyattestation.R;

public record RevocationList(String status, String reason) {

    private static String toString(InputStream input) throws IOException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        } else {
            var output = new ByteArrayOutputStream(8192);
            var buffer = new byte[8192];
            for (int length; (length = input.read(buffer)) != -1; ) {
                output.write(buffer, 0, length);
            }
            return output.toString();
        }
    }

    public static JSONObject parseStatus(InputStream inputStream) throws IOException {
        try {
            var statusListJson = new JSONObject(toString(inputStream));
            return statusListJson.getJSONObject("entries");
        } catch (JSONException e) {
            throw new IOException(e);
        }
    }

    public static JSONObject getStatus() {
        var statusUrl = "https://android.googleapis.com/attestation/status";
        var resName = "android:string/vendor_required_attestation_revocation_list_url";
        var res = AppApplication.app.getResources();
        // noinspection DiscouragedApi
        var id = res.getIdentifier(resName, null, null);
        if (id != 0) {
            var url = res.getString(id);
            if (!statusUrl.equals(url) && url.toLowerCase(Locale.ROOT).startsWith("https")) {
                // no network permission, waiting for user report
                throw new RuntimeException("unknown status url: " + url);
            }
        }
        try (var input = res.openRawResource(R.raw.status)) {
            return RevocationList.parseStatus(input);
        } catch (IOException e) {
            throw new RuntimeException("Failed to parse certificate revocation status", e);
        }
    }

    public static RevocationList decodeStatus(BigInteger serialNumber,
                                              JSONObject entries) {
        String serialNumberString = serialNumber.toString(16).toLowerCase();
        JSONObject revocationStatus;
        try {
            revocationStatus = entries.getJSONObject(serialNumberString);
        } catch (JSONException e) {
            return null;
        }
        try {
            var status = revocationStatus.getString("status");
            var reason = revocationStatus.getString("reason");
            return new RevocationList(status, reason);
        } catch (JSONException e) {
            return new RevocationList("", "");
        }
    }

    @Override
    public String toString() {
        return "status is " + status + ", reason is " + reason;
    }
}
