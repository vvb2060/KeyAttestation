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

import static com.google.common.base.Functions.forMap;
import static com.google.common.collect.Collections2.transform;

import android.security.keystore.KeyProperties;
import android.util.Log;

import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Lists;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1TaggedObject;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.cert.CertificateParsingException;
import java.text.DateFormat;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

import co.nstant.in.cbor.model.DataItem;
import co.nstant.in.cbor.model.Number;
import io.github.vvb2060.keyattestation.AppApplication;

public class AuthorizationList {
    // https://cs.android.com/android/platform/superproject/+/main:hardware/libhardware/include_all/hardware/keymaster_defs.h
    // https://cs.android.com/android/platform/superproject/+/main:frameworks/base/core/java/android/security/keymaster/KeymasterDefs.java

    // Algorithm values.
    public static final int KM_ALGORITHM_RSA = 1;
    public static final int KM_ALGORITHM_EC = 3;
    public static final int KM_ALGORITHM_AES = 32;
    public static final int KM_ALGORITHM_3DES = 33;
    public static final int KM_ALGORITHM_HMAC = 128;

    // EC Curves
    public static final int KM_EC_CURVE_P224 = 0;
    public static final int KM_EC_CURVE_P256 = 1;
    public static final int KM_EC_CURVE_P384 = 2;
    public static final int KM_EC_CURVE_P521 = 3;
    public static final int KM_EC_CURVE_CURVE_25519 = 4;

    // Padding modes.
    public static final int KM_PAD_NONE = 1;
    public static final int KM_PAD_RSA_OAEP = 2;
    public static final int KM_PAD_RSA_PSS = 3;
    public static final int KM_PAD_RSA_PKCS1_1_5_ENCRYPT = 4;
    public static final int KM_PAD_RSA_PKCS1_1_5_SIGN = 5;
    public static final int KM_PAD_PKCS7 = 64;

    // Digest modes.
    public static final int KM_DIGEST_NONE = 0;
    public static final int KM_DIGEST_MD5 = 1;
    public static final int KM_DIGEST_SHA1 = 2;
    public static final int KM_DIGEST_SHA_2_224 = 3;
    public static final int KM_DIGEST_SHA_2_256 = 4;
    public static final int KM_DIGEST_SHA_2_384 = 5;
    public static final int KM_DIGEST_SHA_2_512 = 6;

    // Key origins.
    public static final int KM_ORIGIN_GENERATED = 0;
    public static final int KM_ORIGIN_DERIVED = 1;
    public static final int KM_ORIGIN_IMPORTED = 2;
    public static final int KM_ORIGIN_UNKNOWN = 3;
    public static final int KM_ORIGIN_SECURELY_IMPORTED = 4;

    // Operation Purposes.
    // https://cs.android.com/android/platform/superproject/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/KeyPurpose.aidl
    public static final int KM_PURPOSE_ENCRYPT = 0;
    public static final int KM_PURPOSE_DECRYPT = 1;
    public static final int KM_PURPOSE_SIGN = 2;
    public static final int KM_PURPOSE_VERIFY = 3;
    public static final int KM_PURPOSE_WRAP = 5;
    public static final int KM_PURPOSE_AGREE_KEY = 6;
    public static final int KM_PURPOSE_ATTEST_KEY = 7;

    // User authenticators.
    public static final int HW_AUTH_PASSWORD = 1 << 0;
    public static final int HW_AUTH_BIOMETRIC = 1 << 1;

    // Keymaster tag classes
    public static final int KM_ENUM = 1 << 28;
    public static final int KM_ENUM_REP = 2 << 28;
    public static final int KM_UINT = 3 << 28;
    public static final int KM_UINT_REP = 4 << 28;
    public static final int KM_ULONG = 5 << 28;
    public static final int KM_DATE = 6 << 28;
    public static final int KM_BOOL = 7 << 28;
    public static final int KM_BYTES = 9 << 28;
    public static final int KM_ULONG_REP = 10 << 28;

    // Tag class removal mask
    public static final int KEYMASTER_TAG_TYPE_MASK = 0x0FFFFFFF;

    // Keymaster tags
    // https://cs.android.com/android/platform/superproject/+/main:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/KeyCreationResult.aidl
    public static final int KM_TAG_PURPOSE = KM_ENUM_REP | 1;
    public static final int KM_TAG_ALGORITHM = KM_ENUM | 2;
    public static final int KM_TAG_KEY_SIZE = KM_UINT | 3;
    public static final int KM_TAG_BLOCK_MODE = KM_ENUM_REP | 4;
    public static final int KM_TAG_DIGEST = KM_ENUM_REP | 5;
    public static final int KM_TAG_PADDING = KM_ENUM_REP | 6;
    public static final int KM_TAG_CALLER_NONCE = KM_BOOL | 7;
    public static final int KM_TAG_MIN_MAC_LENGTH = KM_UINT | 8;
    public static final int KM_TAG_KDF = KM_ENUM_REP | 9;
    public static final int KM_TAG_EC_CURVE = KM_ENUM | 10;
    public static final int KM_TAG_RSA_PUBLIC_EXPONENT = KM_ULONG | 200;
    public static final int KM_TAG_RSA_OAEP_MGF_DIGEST = KM_ENUM_REP | 203;
    public static final int KM_TAG_ROLLBACK_RESISTANCE = KM_BOOL | 303;
    public static final int KM_TAG_EARLY_BOOT_ONLY = KM_BOOL | 305;
    public static final int KM_TAG_ACTIVE_DATETIME = KM_DATE | 400;
    public static final int KM_TAG_ORIGINATION_EXPIRE_DATETIME = KM_DATE | 401;
    public static final int KM_TAG_USAGE_EXPIRE_DATETIME = KM_DATE | 402;
    public static final int KM_TAG_USAGE_COUNT_LIMIT = KM_UINT | 405;
    public static final int KM_TAG_NO_AUTH_REQUIRED = KM_BOOL | 503;
    public static final int KM_TAG_USER_AUTH_TYPE = KM_ENUM | 504;
    public static final int KM_TAG_AUTH_TIMEOUT = KM_UINT | 505;
    public static final int KM_TAG_ALLOW_WHILE_ON_BODY = KM_BOOL | 506;
    public static final int KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED = KM_BOOL | 507;
    public static final int KM_TAG_TRUSTED_CONFIRMATION_REQUIRED = KM_BOOL | 508;
    public static final int KM_TAG_UNLOCKED_DEVICE_REQUIRED = KM_BOOL | 509;
    public static final int KM_TAG_ALL_APPLICATIONS = KM_BOOL | 600;
    public static final int KM_TAG_APPLICATION_ID = KM_BYTES | 601;
    public static final int KM_TAG_CREATION_DATETIME = KM_DATE | 701;
    public static final int KM_TAG_ORIGIN = KM_ENUM | 702;
    public static final int KM_TAG_ROLLBACK_RESISTANT = KM_BOOL | 703;
    public static final int KM_TAG_ROOT_OF_TRUST = KM_BYTES | 704;
    public static final int KM_TAG_OS_VERSION = KM_UINT | 705;
    public static final int KM_TAG_OS_PATCHLEVEL = KM_UINT | 706;
    public static final int KM_TAG_ATTESTATION_APPLICATION_ID = KM_BYTES | 709;
    public static final int KM_TAG_ATTESTATION_ID_BRAND = KM_BYTES | 710;
    public static final int KM_TAG_ATTESTATION_ID_DEVICE = KM_BYTES | 711;
    public static final int KM_TAG_ATTESTATION_ID_PRODUCT = KM_BYTES | 712;
    public static final int KM_TAG_ATTESTATION_ID_SERIAL = KM_BYTES | 713;
    public static final int KM_TAG_ATTESTATION_ID_IMEI = KM_BYTES | 714;
    public static final int KM_TAG_ATTESTATION_ID_MEID = KM_BYTES | 715;
    public static final int KM_TAG_ATTESTATION_ID_MANUFACTURER = KM_BYTES | 716;
    public static final int KM_TAG_ATTESTATION_ID_MODEL = KM_BYTES | 717;
    public static final int KM_TAG_VENDOR_PATCHLEVEL = KM_UINT | 718;
    public static final int KM_TAG_BOOT_PATCHLEVEL = KM_UINT | 719;
    public static final int KM_TAG_DEVICE_UNIQUE_ATTESTATION = KM_BOOL | 720;
    public static final int KM_TAG_IDENTITY_CREDENTIAL_KEY = KM_BOOL | 721;
    public static final int KM_TAG_ATTESTATION_ID_SECOND_IMEI = KM_BYTES | 723;

    // Map for converting padding values to strings
    private static final ImmutableMap<Integer, String> paddingMap = ImmutableMap
            .<Integer, String>builder()
            .put(KM_PAD_NONE, "NONE")
            .put(KM_PAD_RSA_OAEP, "OAEP")
            .put(KM_PAD_RSA_PSS, "PSS")
            .put(KM_PAD_RSA_PKCS1_1_5_ENCRYPT, "PKCS1 ENCRYPT")
            .put(KM_PAD_RSA_PKCS1_1_5_SIGN, "PKCS1 SIGN")
            .put(KM_PAD_PKCS7, "PKCS7")
            .build();

    // Map for converting digest values to strings
    private static final ImmutableMap<Integer, String> digestMap = ImmutableMap
            .<Integer, String>builder()
            .put(KM_DIGEST_NONE, "NONE")
            .put(KM_DIGEST_MD5, "MD5")
            .put(KM_DIGEST_SHA1, "SHA1")
            .put(KM_DIGEST_SHA_2_224, "SHA224")
            .put(KM_DIGEST_SHA_2_256, "SHA256")
            .put(KM_DIGEST_SHA_2_384, "SHA384")
            .put(KM_DIGEST_SHA_2_512, "SHA512")
            .build();

    // Map for converting purpose values to strings
    private static final ImmutableMap<Integer, String> purposeMap = ImmutableMap
            .<Integer, String>builder()
            .put(KM_PURPOSE_DECRYPT, "DECRYPT")
            .put(KM_PURPOSE_ENCRYPT, "ENCRYPT")
            .put(KM_PURPOSE_SIGN, "SIGN")
            .put(KM_PURPOSE_VERIFY, "VERIFY")
            .put(KM_PURPOSE_WRAP, "WRAP")
            .put(KM_PURPOSE_AGREE_KEY, "AGREE KEY")
            .put(KM_PURPOSE_ATTEST_KEY, "ATTEST KEY")
            .build();

    private Integer securityLevel;
    private Set<Integer> purposes;
    private Integer algorithm;
    private Integer keySize;
    private Set<Integer> digests;
    private Set<Integer> paddingModes;
    private Integer ecCurve;
    private Long rsaPublicExponent;
    private Set<Integer> mgfDigest;
    private Boolean earlyBootOnly;
    private Date activeDateTime;
    private Date originationExpireDateTime;
    private Date usageExpireDateTime;
    private Integer usageCountLimit;
    private Boolean noAuthRequired;
    private Integer userAuthType;
    private Integer authTimeout;
    private Boolean allowWhileOnBody;
    private Boolean allApplications;
    private String applicationId;
    private Date creationDateTime;
    private Integer origin;
    private Boolean rollbackResistant;
    private Boolean rollbackResistance;
    private RootOfTrust rootOfTrust;
    private IntegrityStatus integrityStatus;
    private Integer osVersion;
    private Integer osPatchLevel;
    private Integer vendorPatchLevel;
    private Integer bootPatchLevel;
    private AttestationApplicationId attestationApplicationId;
    private String brand;
    private String device;
    private String serialNumber;
    private String imei;
    private String secondImei;
    private String meid;
    private String product;
    private String manufacturer;
    private String model;
    private Boolean userPresenceRequired;
    private Boolean confirmationRequired;
    private Boolean unlockedDeviceRequired;
    private Boolean deviceUniqueAttestation;
    private Boolean identityCredentialKey;

    public AuthorizationList(ASN1Encodable sequence) throws CertificateParsingException {
        if (!(sequence instanceof ASN1Sequence)) {
            throw new CertificateParsingException("Expected sequence for authorization list, found "
                    + sequence.getClass().getName());
        }

        ASN1SequenceParser parser = ((ASN1Sequence) sequence).parser();
        ASN1TaggedObject entry = parseAsn1TaggedObject(parser);
        for (; entry != null; entry = parseAsn1TaggedObject(parser)) {
            int tag = entry.getTagNo();
            ASN1Primitive value = entry.getBaseObject().toASN1Primitive();
            Log.d(AppApplication.TAG, "Parsing tag: [" + tag + "], value: [" + value + "]");
            switch (tag) {
                default:
                    throw new CertificateParsingException("Unknown tag " + tag + " found");

                case KM_TAG_PURPOSE & KEYMASTER_TAG_TYPE_MASK:
                    purposes = Asn1Utils.getIntegersFromAsn1Set(value);
                    break;
                case KM_TAG_ALGORITHM & KEYMASTER_TAG_TYPE_MASK:
                    algorithm = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case KM_TAG_KEY_SIZE & KEYMASTER_TAG_TYPE_MASK:
                    keySize = Asn1Utils.getIntegerFromAsn1(value);
                    Log.i(AppApplication.TAG, "Found KEY SIZE, value: " + keySize);
                    break;
                case KM_TAG_DIGEST & KEYMASTER_TAG_TYPE_MASK:
                    digests = Asn1Utils.getIntegersFromAsn1Set(value);
                    break;
                case KM_TAG_PADDING & KEYMASTER_TAG_TYPE_MASK:
                    paddingModes = Asn1Utils.getIntegersFromAsn1Set(value);
                    break;
                case KM_TAG_RSA_PUBLIC_EXPONENT & KEYMASTER_TAG_TYPE_MASK:
                    rsaPublicExponent = Asn1Utils.getLongFromAsn1(value);
                    break;
                case KM_TAG_RSA_OAEP_MGF_DIGEST & KEYMASTER_TAG_TYPE_MASK:
                    mgfDigest = Asn1Utils.getIntegersFromAsn1Set(value);
                    break;
                case KM_TAG_EARLY_BOOT_ONLY & KEYMASTER_TAG_TYPE_MASK:
                    earlyBootOnly = true;
                    break;
                case KM_TAG_NO_AUTH_REQUIRED & KEYMASTER_TAG_TYPE_MASK:
                    noAuthRequired = true;
                    break;
                case KM_TAG_CREATION_DATETIME & KEYMASTER_TAG_TYPE_MASK:
                    creationDateTime = Asn1Utils.getDateFromAsn1(value);
                    break;
                case KM_TAG_ORIGIN & KEYMASTER_TAG_TYPE_MASK:
                    origin = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case KM_TAG_OS_VERSION & KEYMASTER_TAG_TYPE_MASK:
                    osVersion = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case KM_TAG_OS_PATCHLEVEL & KEYMASTER_TAG_TYPE_MASK:
                    osPatchLevel = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case KM_TAG_VENDOR_PATCHLEVEL & KEYMASTER_TAG_TYPE_MASK:
                    vendorPatchLevel = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case KM_TAG_BOOT_PATCHLEVEL & KEYMASTER_TAG_TYPE_MASK:
                    bootPatchLevel = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case KM_TAG_ACTIVE_DATETIME & KEYMASTER_TAG_TYPE_MASK:
                    activeDateTime = Asn1Utils.getDateFromAsn1(value);
                    break;
                case KM_TAG_ORIGINATION_EXPIRE_DATETIME & KEYMASTER_TAG_TYPE_MASK:
                    originationExpireDateTime = Asn1Utils.getDateFromAsn1(value);
                    break;
                case KM_TAG_USAGE_EXPIRE_DATETIME & KEYMASTER_TAG_TYPE_MASK:
                    usageExpireDateTime = Asn1Utils.getDateFromAsn1(value);
                    break;
                case KM_TAG_USAGE_COUNT_LIMIT & KEYMASTER_TAG_TYPE_MASK:
                    usageCountLimit = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case KM_TAG_ROLLBACK_RESISTANT & KEYMASTER_TAG_TYPE_MASK:
                    rollbackResistant = true;
                    break;
                case KM_TAG_ROLLBACK_RESISTANCE & KEYMASTER_TAG_TYPE_MASK:
                    rollbackResistance = true;
                    break;
                case KM_TAG_AUTH_TIMEOUT & KEYMASTER_TAG_TYPE_MASK:
                    authTimeout = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case KM_TAG_ALLOW_WHILE_ON_BODY & KEYMASTER_TAG_TYPE_MASK:
                    allowWhileOnBody = true;
                    break;
                case KM_TAG_EC_CURVE & KEYMASTER_TAG_TYPE_MASK:
                    ecCurve = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case KM_TAG_USER_AUTH_TYPE & KEYMASTER_TAG_TYPE_MASK:
                    userAuthType = Asn1Utils.getIntegerFromAsn1(value);
                    break;
                case KM_TAG_ROOT_OF_TRUST & KEYMASTER_TAG_TYPE_MASK:
                    rootOfTrust = new RootOfTrust(value);
                    break;
                case KM_TAG_ATTESTATION_APPLICATION_ID & KEYMASTER_TAG_TYPE_MASK:
                    attestationApplicationId = new AttestationApplicationId(Asn1Utils
                            .getAsn1EncodableFromBytes(Asn1Utils.getByteArrayFromAsn1(value)));
                    break;
                case KM_TAG_ATTESTATION_ID_BRAND & KEYMASTER_TAG_TYPE_MASK:
                    brand = getStringFromAsn1Value(value);
                    break;
                case KM_TAG_ATTESTATION_ID_DEVICE & KEYMASTER_TAG_TYPE_MASK:
                    device = getStringFromAsn1Value(value);
                    break;
                case KM_TAG_ATTESTATION_ID_PRODUCT & KEYMASTER_TAG_TYPE_MASK:
                    product = getStringFromAsn1Value(value);
                    break;
                case KM_TAG_ATTESTATION_ID_SERIAL & KEYMASTER_TAG_TYPE_MASK:
                    serialNumber = getStringFromAsn1Value(value);
                    break;
                case KM_TAG_ATTESTATION_ID_IMEI & KEYMASTER_TAG_TYPE_MASK:
                    imei = getStringFromAsn1Value(value);
                    break;
                case KM_TAG_ATTESTATION_ID_MEID & KEYMASTER_TAG_TYPE_MASK:
                    meid = getStringFromAsn1Value(value);
                    break;
                case KM_TAG_ATTESTATION_ID_MANUFACTURER & KEYMASTER_TAG_TYPE_MASK:
                    manufacturer = getStringFromAsn1Value(value);
                    break;
                case KM_TAG_ATTESTATION_ID_MODEL & KEYMASTER_TAG_TYPE_MASK:
                    model = getStringFromAsn1Value(value);
                    break;
                case KM_TAG_ALL_APPLICATIONS & KEYMASTER_TAG_TYPE_MASK:
                    allApplications = true;
                    break;
                case KM_TAG_APPLICATION_ID & KEYMASTER_TAG_TYPE_MASK:
                    applicationId = new String(Asn1Utils.getByteArrayFromAsn1(value));
                    break;
                case KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED & KEYMASTER_TAG_TYPE_MASK:
                    userPresenceRequired = true;
                    break;
                case KM_TAG_TRUSTED_CONFIRMATION_REQUIRED & KEYMASTER_TAG_TYPE_MASK:
                    confirmationRequired = true;
                    break;
                case KM_TAG_UNLOCKED_DEVICE_REQUIRED & KEYMASTER_TAG_TYPE_MASK:
                    unlockedDeviceRequired = true;
                    break;
                case KM_TAG_DEVICE_UNIQUE_ATTESTATION & KEYMASTER_TAG_TYPE_MASK:
                    deviceUniqueAttestation = true;
                    break;
                case KM_TAG_IDENTITY_CREDENTIAL_KEY & KEYMASTER_TAG_TYPE_MASK:
                    identityCredentialKey = true;
                    break;
                case KM_TAG_ATTESTATION_ID_SECOND_IMEI & KEYMASTER_TAG_TYPE_MASK:
                    secondImei = getStringFromAsn1Value(value);
                    break;
            }
        }

    }

    public AuthorizationList(co.nstant.in.cbor.model.Map submodMap)
            throws CertificateParsingException {
        for (DataItem key : submodMap.getKeys()) {
            int keyInt = ((Number) key).getValue().intValue();
            switch (keyInt) {
                default:
                    throw new CertificateParsingException("Unknown EAT tag: " + key);

                case EatClaim.SECURITY_LEVEL:
                    securityLevel = EatAttestation.eatSecurityLevelToKeymintSecurityLevel(
                            CborUtils.getInt(submodMap, key));
                    break;
                case EatClaim.PURPOSE:
                    purposes = CborUtils.getIntSet(submodMap, key);
                    break;
                case EatClaim.ALGORITHM:
                    algorithm = CborUtils.getInt(submodMap, key);
                    break;
                case EatClaim.KEY_SIZE:
                    keySize = CborUtils.getInt(submodMap, key);
                    Log.i(AppApplication.TAG, "Found KEY SIZE, value: " + keySize);
                    break;
                case EatClaim.DIGEST:
                    digests = CborUtils.getIntSet(submodMap, key);
                    break;
                case EatClaim.PADDING:
                    paddingModes = CborUtils.getIntSet(submodMap, key);
                    break;
                case EatClaim.RSA_PUBLIC_EXPONENT:
                    rsaPublicExponent = CborUtils.getLong(submodMap, key);
                    break;
                case EatClaim.RSA_OAEP_MGF_DIGEST:
                    mgfDigest = CborUtils.getIntSet(submodMap, key);
                    break;
                case EatClaim.NO_AUTH_REQUIRED:
                    noAuthRequired = true;
                    break;
                case EatClaim.IAT:
                    creationDateTime = CborUtils.getDate(submodMap, key);
                    break;
                case EatClaim.ORIGIN:
                    origin = CborUtils.getInt(submodMap, key);
                    break;
                case EatClaim.OS_VERSION:
                    osVersion = CborUtils.getInt(submodMap, key);
                    break;
                case EatClaim.OS_PATCHLEVEL:
                    osPatchLevel = CborUtils.getInt(submodMap, key);
                    break;
                case EatClaim.VENDOR_PATCHLEVEL:
                    vendorPatchLevel = CborUtils.getInt(submodMap, key);
                    break;
                case EatClaim.BOOT_PATCHLEVEL:
                    bootPatchLevel = CborUtils.getInt(submodMap, key);
                    break;
                case EatClaim.ACTIVE_DATETIME:
                    activeDateTime = CborUtils.getDate(submodMap, key);
                    break;
                case EatClaim.ORIGINATION_EXPIRE_DATETIME:
                    originationExpireDateTime = CborUtils.getDate(submodMap, key);
                    break;
                case EatClaim.USAGE_EXPIRE_DATETIME:
                    usageExpireDateTime = CborUtils.getDate(submodMap, key);
                    break;
                case EatClaim.ROLLBACK_RESISTANT:
                    rollbackResistant = true;
                    break;
                case EatClaim.ROLLBACK_RESISTANCE:
                    rollbackResistance = true;
                    break;
                case EatClaim.AUTH_TIMEOUT:
                    authTimeout = CborUtils.getInt(submodMap, key);
                    break;
                case EatClaim.ALLOW_WHILE_ON_BODY:
                    allowWhileOnBody = true;
                    break;
                case EatClaim.EC_CURVE:
                    ecCurve = CborUtils.getInt(submodMap, key);
                    break;
                case EatClaim.USER_AUTH_TYPE:
                    userAuthType = CborUtils.getInt(submodMap, key);
                    break;
                case EatClaim.ATTESTATION_APPLICATION_ID:
                    // TODO: The attestation application ID is currently still encoded as an ASN.1
                    // structure. Parse a CBOR structure when it's available instead.
                    attestationApplicationId = new AttestationApplicationId(
                            Asn1Utils.getAsn1EncodableFromBytes(CborUtils.getBytes(submodMap, key)));
                    break;
                case EatClaim.ATTESTATION_ID_BRAND:
                    brand = CborUtils.getString(submodMap, key);
                    break;
                case EatClaim.ATTESTATION_ID_DEVICE:
                    device = CborUtils.getString(submodMap, key);
                    break;
                case EatClaim.ATTESTATION_ID_PRODUCT:
                    product = CborUtils.getString(submodMap, key);
                    break;
                case EatClaim.ATTESTATION_ID_SERIAL:
                    serialNumber = CborUtils.getString(submodMap, key);
                    break;
                case EatClaim.UEID:
                    // TODO: Parse depending on encoding chosen in attestation_record.cpp.
                    imei = CborUtils.getString(submodMap, key);
                    break;
                case EatClaim.ATTESTATION_ID_MEID:
                    meid = CborUtils.getString(submodMap, key);
                    break;
                case EatClaim.ATTESTATION_ID_MANUFACTURER:
                    manufacturer = CborUtils.getString(submodMap, key);
                    break;
                case EatClaim.ATTESTATION_ID_MODEL:
                    model = CborUtils.getString(submodMap, key);
                    break;
                case EatClaim.USER_PRESENCE_REQUIRED:
                    userPresenceRequired = CborUtils.getBoolean(submodMap, key);
                    break;
                case EatClaim.TRUSTED_CONFIRMATION_REQUIRED:
                    confirmationRequired = true;
                    break;
                case EatClaim.UNLOCKED_DEVICE_REQUIRED:
                    unlockedDeviceRequired = true;
                    break;
                case EatClaim.APPLICATION_ID:
                    applicationId = CborUtils.getString(submodMap, key);
                case EatClaim.EARLY_BOOT_ONLY:
                    earlyBootOnly = true;
                    break;
                case EatClaim.DEVICE_UNIQUE_ATTESTATION:
                    deviceUniqueAttestation = true;
                    break;
            }
        }
    }

    public static String algorithmToString(int algorithm) {
        switch (algorithm) {
            case KM_ALGORITHM_RSA:
                return "RSA";
            case KM_ALGORITHM_EC:
                return "ECDSA";
            case KM_ALGORITHM_AES:
                return "AES";
            case KM_ALGORITHM_3DES:
                return "3DES";
            case KM_ALGORITHM_HMAC:
                return "HMAC";
            default:
                return "Unknown (" + algorithm + ")";
        }
    }

    public static String paddingModesToString(final Set<Integer> paddingModes) {
        return joinStrings(transform(paddingModes, forMap(paddingMap, "Unknown")));
    }

    public static String paddingModeToString(int paddingMode) {
        return forMap(paddingMap, "Unknown").apply(paddingMode);
    }

    public static String digestsToString(Set<Integer> digests) {
        return joinStrings(transform(digests, forMap(digestMap, "Unknown")));
    }

    public static String digestToString(int digest) {
        return forMap(digestMap, "Unknown").apply(digest);
    }

    public static String purposesToString(Set<Integer> purposes) {
        return joinStrings(transform(purposes, forMap(purposeMap, "Unknown")));
    }

    public static String userAuthTypeToString(int userAuthType) {
        List<String> types = Lists.newArrayList();
        if ((userAuthType & HW_AUTH_BIOMETRIC) != 0)
            types.add("Biometric");
        if ((userAuthType & HW_AUTH_PASSWORD) != 0)
            types.add("Password");
        return joinStrings(types);
    }

    public static String originToString(int origin) {
        switch (origin) {
            case KM_ORIGIN_GENERATED:
                return "Generated";
            case KM_ORIGIN_DERIVED:
                return "Derived";
            case KM_ORIGIN_IMPORTED:
                return "Imported";
            case KM_ORIGIN_UNKNOWN:
                return "Unknown (KM0)";
            case KM_ORIGIN_SECURELY_IMPORTED:
                return "Securely Imported";
            default:
                return "Unknown (" + origin + ")";
        }
    }

    private static String joinStrings(Collection<String> collection) {
        return "[" + Joiner.on(", ").join(collection) + "]";
    }

    public static String formatDate(Date date) {
        return DateFormat.getDateTimeInstance().format(date);
    }

    private static ASN1TaggedObject parseAsn1TaggedObject(ASN1SequenceParser parser)
            throws CertificateParsingException {
        ASN1Encodable asn1Encodable = parseAsn1Encodable(parser);
        if (asn1Encodable == null || asn1Encodable instanceof ASN1TaggedObject) {
            return (ASN1TaggedObject) asn1Encodable;
        }
        throw new CertificateParsingException(
                "Expected tagged object, found " + asn1Encodable.getClass().getName());
    }

    private static ASN1Encodable parseAsn1Encodable(ASN1SequenceParser parser)
            throws CertificateParsingException {
        try {
            return parser.readObject();
        } catch (IOException e) {
            throw new CertificateParsingException("Failed to parse ASN1 sequence", e);
        }
    }

    public Integer getSecurityLevel() {
        return securityLevel;
    }

    public Set<Integer> getPurposes() {
        return purposes;
    }

    public Integer getAlgorithm() {
        return algorithm;
    }

    public Integer getKeySize() {
        return keySize;
    }

    public Set<Integer> getDigests() {
        return digests;
    }

    public Set<Integer> getPaddingModes() {
        return paddingModes;
    }

    public Set<String> getPaddingModesAsStrings() throws CertificateParsingException {
        if (paddingModes == null) {
            return ImmutableSet.of();
        }

        ImmutableSet.Builder<String> builder = ImmutableSet.builder();
        for (int paddingMode : paddingModes) {
            switch (paddingMode) {
                case KM_PAD_NONE:
                    builder.add(KeyProperties.ENCRYPTION_PADDING_NONE);
                    break;
                case KM_PAD_RSA_OAEP:
                    builder.add(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP);
                    break;
                case KM_PAD_RSA_PKCS1_1_5_ENCRYPT:
                    builder.add(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1);
                    break;
                case KM_PAD_RSA_PKCS1_1_5_SIGN:
                    builder.add(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1);
                    break;
                case KM_PAD_PKCS7:
                    builder.add(KeyProperties.ENCRYPTION_PADDING_PKCS7);
                    break;
                case KM_PAD_RSA_PSS:
                    builder.add(KeyProperties.SIGNATURE_PADDING_RSA_PSS);
                    break;
                default:
                    throw new CertificateParsingException("Invalid padding mode " + paddingMode);
            }
        }
        return builder.build();
    }

    public Integer getEcCurve() {
        return ecCurve;
    }

    public static String ecCurveAsString(Integer ecCurve) {
        if (ecCurve == null)
            return "NULL";

        switch (ecCurve) {
            case KM_EC_CURVE_P224:
                return "secp224r1";
            case KM_EC_CURVE_P256:
                return "secp256r1";
            case KM_EC_CURVE_P384:
                return "secp384r1";
            case KM_EC_CURVE_P521:
                return "secp521r1";
            case KM_EC_CURVE_CURVE_25519:
                return "CURVE_25519";
            default:
                return "unknown (" + ecCurve + ")";
        }
    }

    public Long getRsaPublicExponent() {
        return rsaPublicExponent;
    }

    public Date getActiveDateTime() {
        return activeDateTime;
    }

    public Date getOriginationExpireDateTime() {
        return originationExpireDateTime;
    }

    public Date getUsageExpireDateTime() {
        return usageExpireDateTime;
    }

    public Boolean getNoAuthRequired() {
        return noAuthRequired;
    }

    public Integer getUserAuthType() {
        return userAuthType;
    }

    public Integer getAuthTimeout() {
        return authTimeout;
    }

    public Boolean getAllowWhileOnBody() {
        return allowWhileOnBody;
    }

    public Boolean getAllApplications() {
        return allApplications;
    }

    public String getApplicationId() {
        return applicationId;
    }

    public Date getCreationDateTime() {
        return creationDateTime;
    }

    public Integer getOrigin() {
        return origin;
    }

    public Boolean getRollbackResistant() {
        return rollbackResistant;
    }

    public Boolean getRollbackResistance() {
        return rollbackResistance;
    }

    public Boolean getUnlockedDeviceRequired() {
        return unlockedDeviceRequired;
    }

    public RootOfTrust getRootOfTrust() {
        return rootOfTrust;
    }

    public IntegrityStatus getIntegrityStatus() {
        return integrityStatus;
    }

    void setIntegrityStatus(IntegrityStatus is) {
        integrityStatus = is;
    }

    public Integer getOsVersion() {
        return osVersion;
    }

    public Integer getOsPatchLevel() {
        return osPatchLevel;
    }

    public Integer getVendorPatchLevel() {
        return vendorPatchLevel;
    }

    public Integer getBootPatchLevel() {
        return bootPatchLevel;
    }

    public AttestationApplicationId getAttestationApplicationId() {
        return attestationApplicationId;
    }

    public String getBrand() {
        return brand;
    }

    public String getDevice() {
        return device;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public String getImei() {
        return imei;
    }

    public String getSecondImei() {
        return secondImei;
    }

    public String getMeid() {
        return meid;
    }

    public String getProduct() {
        return product;
    }

    public String getManufacturer() {
        return manufacturer;
    }

    public String getModel() {
        return model;
    }

    public Boolean getUserPresenceRequired() {
        return userPresenceRequired;
    }

    public Boolean getConfirmationRequired() {
        return confirmationRequired;
    }

    public Set<Integer> getMgfDigest() {
        return mgfDigest;
    }

    public Boolean getEarlyBootOnly() {
        return earlyBootOnly;
    }

    public Integer getUsageCountLimit() {
        return usageCountLimit;
    }

    public Boolean getDeviceUniqueAttestation() {
        return deviceUniqueAttestation;
    }

    public Boolean getIdentityCredentialKey() {
        return identityCredentialKey;
    }

    private String getStringFromAsn1Value(ASN1Primitive value) throws CertificateParsingException {
        try {
            return Asn1Utils.getStringFromAsn1OctetStreamAssumingUTF8(value);
        } catch (UnsupportedEncodingException e) {
            throw new CertificateParsingException("Error parsing ASN.1 value", e);
        }
    }

    @Override
    public String toString() {
        StringBuilder s = new StringBuilder();

        if (algorithm != null) {
            s.append("\nAlgorithm: ").append(algorithmToString(algorithm));
        }

        if (keySize != null) {
            s.append("\nKeySize: ").append(keySize);
        }

        if (purposes != null && !purposes.isEmpty()) {
            s.append("\nPurposes: ").append(purposesToString(purposes));
        }

        if (digests != null && !digests.isEmpty()) {
            s.append("\nDigests: ").append(digestsToString(digests));
        }

        if (paddingModes != null && !paddingModes.isEmpty()) {
            s.append("\nPadding modes: ").append(paddingModesToString(paddingModes));
        }

        if (ecCurve != null) {
            s.append("\nEC Curve: ").append(ecCurveAsString(ecCurve));
        }

        if (rsaPublicExponent != null) {
            s.append("\nRSA exponent: ").append(rsaPublicExponent);
        }

        if (mgfDigest != null && !mgfDigest.isEmpty()) {
            s.append("\nRsa Oaep Mgf Digest: ").append(digestsToString(mgfDigest));
        }

        if (earlyBootOnly != null) {
            s.append("\nEarly boot only");
        }

        if (activeDateTime != null) {
            s.append("\nActive: ").append(formatDate(activeDateTime));
        }

        if (originationExpireDateTime != null) {
            s.append("\nOrigination expire: ").append(formatDate(originationExpireDateTime));
        }

        if (usageExpireDateTime != null) {
            s.append("\nUsage expire: ").append(formatDate(usageExpireDateTime));
        }

        if (usageCountLimit != null) {
            s.append("\nUsage count limit: ").append(usageCountLimit);
        }

        if (noAuthRequired != null) {
            s.append("\nNo Auth Required");
        }

        if (userAuthType != null) {
            s.append("\nAuth types: ").append(userAuthTypeToString(userAuthType));
        }

        if (authTimeout != null) {
            s.append("\nAuth timeout: ").append(authTimeout);
        }

        if (allowWhileOnBody != null) {
            s.append("\nAllow While On Body");
        }

        if (allApplications != null) {
            s.append("\nAll Applications");
        }

        if (applicationId != null) {
            s.append("\nApplication ID: ").append(applicationId);
        }

        if (creationDateTime != null) {
            s.append("\nCreated: ").append(formatDate(creationDateTime));
        }

        if (origin != null) {
            s.append("\nOrigin: ").append(originToString(origin));
        }

        if (rollbackResistant != null) {
            s.append("\nRollback resistant");
        }

        if (rollbackResistance != null) {
            s.append("\nRollback resistance");
        }

        if (rootOfTrust != null) {
            s.append("\nRoot of Trust:\n");
            s.append(rootOfTrust);
        }

        if (integrityStatus != null) {
            s.append("\nIntegrity Status:\n");
            s.append(integrityStatus);
            if (integrityStatus.getAuthResult() != null) {
                s.append("\nCaller Auth Status:\n");
                s.append(integrityStatus.getAuthResult());
            }
        }

        if (osVersion != null) {
            s.append("\nOS Version: ").append(osVersion);
        }

        if (osPatchLevel != null) {
            s.append("\nOS Patchlevel: ").append(osPatchLevel);
        }

        if (vendorPatchLevel != null) {
            s.append("\nVendor Patchlevel: ").append(vendorPatchLevel);
        }

        if (bootPatchLevel != null) {
            s.append("\nBoot Patchlevel: ").append(bootPatchLevel);
        }

        if (attestationApplicationId != null) {
            s.append("\nAttestation Application Id:\n").append(attestationApplicationId);
        }

        if (userPresenceRequired != null) {
            s.append("\nUser presence required");
        }

        if (confirmationRequired != null) {
            s.append("\nConfirmation required");
        }

        if (unlockedDeviceRequired != null) {
            s.append("\nUnlocked Device Required");
        }

        if (deviceUniqueAttestation != null) {
            s.append("\nDevice unique attestation");
        }

        if (identityCredentialKey != null) {
            s.append("\nIdentity Credential Key");
        }

        if (brand != null) {
            s.append("\nBrand: ").append(brand);
        }
        if (device != null) {
            s.append("\nDevice type: ").append(device);
        }
        if (product != null) {
            s.append("\nProduct: ").append(product);
        }
        if (serialNumber != null) {
            s.append("\nSerial: ").append(serialNumber);
        }
        if (imei != null) {
            s.append("\nIMEI: ").append(imei);
        }
        if (secondImei != null) {
            s.append("\nSecond IMEI:").append(secondImei);
        }
        if (meid != null) {
            s.append("\nMEID: ").append(meid);
        }
        if (manufacturer != null) {
            s.append("\nManufacturer: ").append(manufacturer);
        }
        if (model != null) {
            s.append("\nModel: ").append(model);
        }
        return s.toString();
    }
}
