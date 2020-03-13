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

package io.github.vvb2060.keyattestation.server;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
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

    public static CertificateRevocationStatus loadStatusFromFile(BigInteger serialNumber,
                                                                 InputStreamReader reader) {
        return decodeStatus(serialNumber.toString(16), reader);
    }

    public static CertificateRevocationStatus fetchStatus(BigInteger serialNumber) throws IOException {
        URL url = new URL(STATUS_URL);

        InputStreamReader statusListReader = new InputStreamReader(url.openStream());

        return decodeStatus(serialNumber.toString(16), statusListReader);

    }

    private static CertificateRevocationStatus decodeStatus(String serialNumber,
                                                            Reader statusListReader) {
        if (serialNumber == null) {
            throw new IllegalArgumentException("serialNumber cannot be null");
        }
        serialNumber = serialNumber.toLowerCase();

        JsonObject entries = JsonParser.parseReader(statusListReader)
                .getAsJsonObject()
                .getAsJsonObject("entries");

        if (!entries.has(serialNumber)) {
            return null;
        }

        return new Gson().fromJson(entries.get(serialNumber), CertificateRevocationStatus.class);
    }

    public enum Status {
        REVOKED, SUSPENDED
    }

    public enum Reason {
        UNSPECIFIED, KEY_COMPROMISE, CA_COMPROMISE, SUPERSEDED, SOFTWARE_FLAW
    }
}
