/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.github.vvb2060.keyattestation.attestation;

import com.google.common.collect.ImmutableSet;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateParsingException;
import java.util.Date;
import java.util.Enumeration;
import java.util.Set;

public class Asn1Utils {

    public static int getIntegerFromAsn1(ASN1Encodable asn1Value)
            throws CertificateParsingException {
        if (asn1Value instanceof ASN1Integer) {
            return bigIntegerToInt(((ASN1Integer) asn1Value).getValue());
        } else if (asn1Value instanceof ASN1Enumerated) {
            return bigIntegerToInt(((ASN1Enumerated) asn1Value).getValue());
        } else {
            throw new CertificateParsingException(
                    "Integer value expected, " + asn1Value.getClass().getName() + " found.");
        }
    }

    public static Long getLongFromAsn1(ASN1Encodable asn1Value) throws CertificateParsingException {
        if (asn1Value instanceof ASN1Integer) {
            return bigIntegerToLong(((ASN1Integer) asn1Value).getValue());
        } else {
            throw new CertificateParsingException(
                    "Integer value expected, " + asn1Value.getClass().getName() + " found.");
        }
    }

    public static byte[] getByteArrayFromAsn1(ASN1Encodable asn1Encodable)
            throws CertificateParsingException {
        if (asn1Encodable == null) {
            throw new CertificateParsingException("Expected DEROctetString");
        }
        if (asn1Encodable instanceof DEROctetString) {
            return ((ASN1OctetString) asn1Encodable).getOctets();
        }
        if (asn1Encodable instanceof DERPrintableString) {
            return ((DERPrintableString) asn1Encodable).getOctets();
        }
        throw new CertificateParsingException("Expected DEROctetString");
    }

    public static ASN1Encodable getAsn1EncodableFromBytes(byte[] bytes)
            throws CertificateParsingException {
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(bytes)) {
            return asn1InputStream.readObject();
        } catch (IOException e) {
            throw new CertificateParsingException("Failed to parse Encodable", e);
        }
    }

    public static ASN1Sequence getAsn1SequenceFromBytes(byte[] bytes)
            throws CertificateParsingException {
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(bytes)) {
            return getAsn1SequenceFromStream(asn1InputStream);
        } catch (IOException e) {
            throw new CertificateParsingException("Failed to parse SEQUENCE", e);
        }
    }

    public static ASN1Sequence getAsn1SequenceFromStream(final ASN1InputStream asn1InputStream)
            throws IOException, CertificateParsingException {
        ASN1Primitive asn1Primitive = asn1InputStream.readObject();
        if (!(asn1Primitive instanceof ASN1OctetString)) {
            throw new CertificateParsingException(
                    "Expected octet stream, found " + asn1Primitive.getClass().getName());
        }
        try (ASN1InputStream seqInputStream = new ASN1InputStream(
                ((ASN1OctetString) asn1Primitive).getOctets())) {
            asn1Primitive = seqInputStream.readObject();
            if (!(asn1Primitive instanceof ASN1Sequence)) {
                throw new CertificateParsingException(
                        "Expected sequence, found " + asn1Primitive.getClass().getName());
            }
            return (ASN1Sequence) asn1Primitive;
        }
    }

    public static Set<Integer> getIntegersFromAsn1Set(ASN1Encodable set)
            throws CertificateParsingException {
        if (!(set instanceof ASN1Set)) {
            throw new CertificateParsingException(
                    "Expected set, found " + set.getClass().getName());
        }

        ImmutableSet.Builder<Integer> builder = ImmutableSet.builder();
        for (Enumeration<?> e = ((ASN1Set) set).getObjects(); e.hasMoreElements();) {
            builder.add(getIntegerFromAsn1((ASN1Integer) e.nextElement()));
        }
        return builder.build();
    }

    public static String getStringFromAsn1OctetStreamAssumingUTF8(ASN1Encodable encodable)
            throws CertificateParsingException, UnsupportedEncodingException {
        if (!(encodable instanceof ASN1OctetString)) {
            throw new CertificateParsingException(
                    "Expected octet string, found " + encodable.getClass().getName());
        }

        ASN1OctetString octetString = (ASN1OctetString) encodable;
        return new String(octetString.getOctets(), StandardCharsets.UTF_8);
    }

    public static Date getDateFromAsn1(ASN1Primitive value) throws CertificateParsingException {
        return new Date(getLongFromAsn1(value));
    }

    public static boolean getBooleanFromAsn1(ASN1Encodable value)
            throws CertificateParsingException {
        if (!(value instanceof ASN1Boolean)) {
            throw new CertificateParsingException(
                    "Expected boolean, found " + value.getClass().getName());
        }
        ASN1Boolean booleanValue = (ASN1Boolean) value;
        if (booleanValue.equals(ASN1Boolean.TRUE)) {
            return true;
        } else if (booleanValue.equals((ASN1Boolean.FALSE))) {
            return false;
        }

        throw new CertificateParsingException(
                "DER-encoded boolean values must contain either 0x00 or 0xFF");
    }

    private static int bigIntegerToInt(BigInteger bigInt) throws CertificateParsingException {
        if (bigInt.compareTo(BigInteger.valueOf(Integer.MAX_VALUE)) > 0
                || bigInt.compareTo(BigInteger.ZERO) < 0) {
            throw new CertificateParsingException("INTEGER out of bounds");
        }
        return bigInt.intValue();
    }

    private static long bigIntegerToLong(BigInteger bigInt) throws CertificateParsingException {
        if (bigInt.compareTo(BigInteger.valueOf(Long.MAX_VALUE)) > 0
                || bigInt.compareTo(BigInteger.ZERO) < 0) {
            throw new CertificateParsingException("INTEGER out of bounds");
        }
        return bigInt.longValue();
    }
}
