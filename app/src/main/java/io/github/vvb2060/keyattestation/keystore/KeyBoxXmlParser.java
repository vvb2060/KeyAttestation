package io.github.vvb2060.keyattestation.keystore;

import android.util.Base64;
import android.util.Xml;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

public class KeyBoxXmlParser {
    private final XmlPullParser parser;
    private final CertificateFactory certificateFactory;
    private final List<Certificate> chain;
    private PrivateKey privateKey;

    private static KeyBoxXmlParser instance;

    public static KeyBoxXmlParser getInstance() throws IOException {
        if (instance == null) {
            instance = new KeyBoxXmlParser();
        }
        return instance;
    }

    private KeyBoxXmlParser() throws IOException {
        parser = Xml.newPullParser();
        chain = new ArrayList<>();
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    public KeyStore.PrivateKeyEntry parse(InputStream in) throws IOException {
        try {
            parser.setInput(in, StandardCharsets.UTF_8.name());
            chain.clear();
            privateKey = null;
            readAndroidAttestation();
        } catch (XmlPullParserException e) {
            throw new IOException(e);
        }
        if (privateKey == null || chain.isEmpty()) {
            throw new IOException("No key found");
        }
        return new KeyStore.PrivateKeyEntry(privateKey, chain.toArray(new Certificate[0]));
    }

    private void readAndroidAttestation() throws XmlPullParserException, IOException {
        while (parser.next() != XmlPullParser.END_DOCUMENT) {
            if (parser.getEventType() != XmlPullParser.START_TAG) {
                continue;
            }
            var name = parser.getName();
            var algorithm = parser.getAttributeValue(null, "algorithm");
            if ("Key".equals(name) && "ecdsa".equals(algorithm)) {
                parser.nextTag();
                readECKey();
                break;
            }
        }
    }

    private void readECKey() throws XmlPullParserException, IOException {
        while (!(parser.getEventType() == XmlPullParser.END_TAG && "Key".equals(parser.getName()))) {
            if (parser.getEventType() != XmlPullParser.START_TAG) {
                parser.next();
                continue;
            }
            var format = parser.getAttributeValue(null, "format");
            switch (parser.getName()) {
                case "PrivateKey" -> {
                    if ("pem".equals(format)) {
                        parser.next();
                        readPrivateKey(parser.getText());
                        parser.next();
                    } else {
                        return;
                    }
                }
                case "Certificate" -> {
                    if ("pem".equals(format)) {
                        parser.next();
                        readCertificateChain(parser.getText());
                        parser.next();
                    } else {
                        return;
                    }
                }
                default -> parser.next();
            }
        }
    }

    private static byte[] stringToBytes(String text) {
        var sb = new StringBuilder();
        for (var s : text.split("\n")) {
            var line = s.trim();
            if (line.isEmpty()) continue;
            if (line.charAt(0) == '-') continue;
            sb.append(line);
            sb.append("\n");
        }
        return Base64.decode(sb.toString(), 0);
    }

    private void readPrivateKey(String text) throws IOException {
        try {
            var sequence = ASN1Sequence.getInstance(stringToBytes(text));
            var ecKey = ECPrivateKey.getInstance(sequence);
            var id = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
                    ecKey.getParametersObject());
            var data = new PrivateKeyInfo(id, ecKey).getEncoded();
            var keySpec = new PKCS8EncodedKeySpec(data);
            var keyFactory = KeyFactory.getInstance("EC");
            privateKey = keyFactory.generatePrivate(keySpec);
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    private void readCertificateChain(String text) throws IOException {
        try {
            var data = new ByteArrayInputStream(stringToBytes(text));
            chain.add(certificateFactory.generateCertificate(data));
        } catch (CertificateException e) {
            throw new IOException(e);
        }
    }
}
