/* Copyright 2019, The Android Open Source Project, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.github.vvb2060.keyattestation.attestation;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.URL;


/**
 * Utils for fetching and decoding attestation certificate status.
 */
public class CertificateRevocationStatus {

    private static final String STATUS_URL = "https://android.googleapis.com/attestation/status";
    public final Status status;
    public final Reason reason;
    public final String comment;
    public final String expires;

    public CertificateRevocationStatus() {
        status = Status.REVOKED;
        reason = Reason.UNSPECIFIED;
        comment = null;
        expires = null;
    }

    public static JsonObject parseStatus(InputStream stream) {
        return JsonParser.parseReader(new InputStreamReader(stream))
                .getAsJsonObject()
                .getAsJsonObject("entries");
    }

    public static CertificateRevocationStatus fetchStatus(BigInteger serialNumber) throws IOException {
        URL url = new URL(STATUS_URL);
        return decodeStatus(serialNumber, parseStatus(url.openStream()));
    }

    public static CertificateRevocationStatus decodeStatus(BigInteger serialNumber,
                                                           JsonObject entries) {
        if (serialNumber == null) {
            throw new IllegalArgumentException("serialNumber cannot be null");
        }
        String serialNumberString = serialNumber.toString(16).toLowerCase();
        if (!entries.has(serialNumberString)) {
            return null;
        }
        return new Gson().fromJson(entries.get(serialNumberString), CertificateRevocationStatus.class);
    }

    public enum Status {
        REVOKED, SUSPENDED
    }

    public enum Reason {
        UNSPECIFIED, KEY_COMPROMISE, CA_COMPROMISE, SUPERSEDED, SOFTWARE_FLAW
    }
}
