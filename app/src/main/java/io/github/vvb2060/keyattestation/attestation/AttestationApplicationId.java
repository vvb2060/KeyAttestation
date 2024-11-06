/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package io.github.vvb2060.keyattestation.attestation;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.content.pm.Signature;

import com.google.common.io.BaseEncoding;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.List;

public class AttestationApplicationId implements java.lang.Comparable<AttestationApplicationId> {
    private static final int PACKAGE_INFOS_INDEX = 0;
    private static final int SIGNATURE_DIGESTS_INDEX = 1;

    private final List<AttestationPackageInfo> packageInfos;
    private final List<byte[]> signatureDigests;

    public AttestationApplicationId(Context context)
            throws NoSuchAlgorithmException, NameNotFoundException {
        PackageManager pm = context.getPackageManager();
        int uid = context.getApplicationInfo().uid;
        String[] packageNames = pm.getPackagesForUid(uid);
        if (packageNames == null || packageNames.length == 0) {
            throw new NameNotFoundException("No names found for uid");
        }
        packageInfos = new ArrayList<AttestationPackageInfo>();
        for (String packageName : packageNames) {
            // get the package info for the given package name including
            // the signatures
            PackageInfo packageInfo = pm.getPackageInfo(packageName, 0);
            packageInfos.add(new AttestationPackageInfo(packageName, packageInfo.versionCode));
        }
        // The infos must be sorted, the implementation of Comparable relies on it.
        packageInfos.sort(null);

        // compute the sha256 digests of the signature blobs
        signatureDigests = new ArrayList<byte[]>();
        PackageInfo packageInfo = pm.getPackageInfo(packageNames[0], PackageManager.GET_SIGNATURES);
        for (Signature signature : packageInfo.signatures) {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            signatureDigests.add(sha256.digest(signature.toByteArray()));
        }
        // The digests must be sorted. the implementation of Comparable relies on it
        signatureDigests.sort(new ByteArrayComparator());
    }

    public AttestationApplicationId(ASN1Encodable asn1Encodable)
            throws CertificateParsingException {
        if (!(asn1Encodable instanceof ASN1Sequence sequence)) {
            throw new CertificateParsingException(
                    "Expected sequence for AttestationApplicationId, found "
                            + asn1Encodable.getClass().getName());
        }

        packageInfos = parseAttestationPackageInfos(sequence.getObjectAt(PACKAGE_INFOS_INDEX));
        // The infos must be sorted, the implementation of Comparable relies on it.
        packageInfos.sort(null);
        signatureDigests = parseSignatures(sequence.getObjectAt(SIGNATURE_DIGESTS_INDEX));
        // The digests must be sorted. the implementation of Comparable relies on it
        signatureDigests.sort(new ByteArrayComparator());
    }

    public List<AttestationPackageInfo> getAttestationPackageInfos() {
        return packageInfos;
    }

    public List<byte[]> getSignatureDigests() {
        return signatureDigests;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        int noOfInfos = packageInfos.size();
        int i = 1;
        for (AttestationPackageInfo info : packageInfos) {
            sb.append("Package info " + i++ + "/" + noOfInfos + ":\n");
            sb.append(info);
            sb.append('\n');
        }
        sb.append('\n');
        i = 1;
        int noOfSigs = signatureDigests.size();
        for (byte[] sig : signatureDigests) {
            sb.append("Certificate sha256 digest " + i++ + "/" + noOfSigs + ":\n");
            sb.append(BaseEncoding.base16().lowerCase().encode(sig));
            sb.append('\n');
        }
        return sb.toString();
    }

    @Override
    public int compareTo(AttestationApplicationId other) {
        int res = Integer.compare(packageInfos.size(), other.packageInfos.size());
        if (res != 0) return res;
        for (int i = 0; i < packageInfos.size(); ++i) {
            res = packageInfos.get(i).compareTo(other.packageInfos.get(i));
            if (res != 0) return res;
        }
        res = Integer.compare(signatureDigests.size(), other.signatureDigests.size());
        if (res != 0) return res;
        ByteArrayComparator cmp = new ByteArrayComparator();
        for (int i = 0; i < signatureDigests.size(); ++i) {
            res = cmp.compare(signatureDigests.get(i), other.signatureDigests.get(i));
            if (res != 0) return res;
        }
        return res;
    }

    @Override
    public boolean equals(Object o) {
        return (o instanceof AttestationApplicationId)
                && (0 == compareTo((AttestationApplicationId) o));
    }

    private List<AttestationPackageInfo> parseAttestationPackageInfos(ASN1Encodable asn1Encodable)
            throws CertificateParsingException {
        if (!(asn1Encodable instanceof ASN1Set set)) {
            throw new CertificateParsingException(
                    "Expected set for AttestationApplicationsInfos, found "
                            + asn1Encodable.getClass().getName());
        }

        List<AttestationPackageInfo> result = new ArrayList<AttestationPackageInfo>();
        for (ASN1Encodable e : set) {
            result.add(new AttestationPackageInfo(e));
        }
        return result;
    }

    private List<byte[]> parseSignatures(ASN1Encodable asn1Encodable)
            throws CertificateParsingException {
        if (!(asn1Encodable instanceof ASN1Set set)) {
            throw new CertificateParsingException("Expected set for Signature digests, found "
                    + asn1Encodable.getClass().getName());
        }

        List<byte[]> result = new ArrayList<byte[]>();

        for (ASN1Encodable e : set) {
            result.add(Asn1Utils.getByteArrayFromAsn1(e));
        }
        return result;
    }

    private static class ByteArrayComparator implements java.util.Comparator<byte[]> {
        @Override
        public int compare(byte[] a, byte[] b) {
            int res = Integer.compare(a.length, b.length);
            if (res != 0) return res;
            for (int i = 0; i < a.length; ++i) {
                res = Byte.compare(a[i], b[i]);
                if (res != 0) return res;
            }
            return res;
        }
    }
}
