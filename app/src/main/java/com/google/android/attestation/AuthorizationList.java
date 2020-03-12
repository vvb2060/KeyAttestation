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

package com.google.android.attestation;

import static com.google.android.attestation.AuthorizationList.UserAuthType.FINGERPRINT;
import static com.google.android.attestation.AuthorizationList.UserAuthType.PASSWORD;
import static com.google.android.attestation.AuthorizationList.UserAuthType.USER_AUTH_TYPE_ANY;
import static com.google.android.attestation.AuthorizationList.UserAuthType.USER_AUTH_TYPE_NONE;
import static com.google.android.attestation.Constants.KM_TAG_ACTIVE_DATE_TIME;
import static com.google.android.attestation.Constants.KM_TAG_ALGORITHM;
import static com.google.android.attestation.Constants.KM_TAG_ALLOW_WHILE_ON_BODY;
import static com.google.android.attestation.Constants.KM_TAG_ALL_APPLICATIONS;
import static com.google.android.attestation.Constants.KM_TAG_APPLICATION_ID;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_APPLICATION_ID;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_BRAND;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_DEVICE;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_IMEI;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_MANUFACTURER;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_MEID;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_MODEL;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_PRODUCT;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_SERIAL;
import static com.google.android.attestation.Constants.KM_TAG_AUTH_TIMEOUT;
import static com.google.android.attestation.Constants.KM_TAG_BOOT_PATCH_LEVEL;
import static com.google.android.attestation.Constants.KM_TAG_CREATION_DATE_TIME;
import static com.google.android.attestation.Constants.KM_TAG_DIGEST;
import static com.google.android.attestation.Constants.KM_TAG_EC_CURVE;
import static com.google.android.attestation.Constants.KM_TAG_KEY_SIZE;
import static com.google.android.attestation.Constants.KM_TAG_NO_AUTH_REQUIRED;
import static com.google.android.attestation.Constants.KM_TAG_ORIGIN;
import static com.google.android.attestation.Constants.KM_TAG_ORIGINATION_EXPIRE_DATE_TIME;
import static com.google.android.attestation.Constants.KM_TAG_OS_PATCH_LEVEL;
import static com.google.android.attestation.Constants.KM_TAG_OS_VERSION;
import static com.google.android.attestation.Constants.KM_TAG_PADDING;
import static com.google.android.attestation.Constants.KM_TAG_PURPOSE;
import static com.google.android.attestation.Constants.KM_TAG_ROLLBACK_RESISTANCE;
import static com.google.android.attestation.Constants.KM_TAG_ROLLBACK_RESISTANT;
import static com.google.android.attestation.Constants.KM_TAG_ROOT_OF_TRUST;
import static com.google.android.attestation.Constants.KM_TAG_RSA_PUBLIC_EXPONENT;
import static com.google.android.attestation.Constants.KM_TAG_TRUSTED_CONFIRMATION_REQUIRED;
import static com.google.android.attestation.Constants.KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED;
import static com.google.android.attestation.Constants.KM_TAG_UNLOCKED_DEVICE_REQUIRED;
import static com.google.android.attestation.Constants.KM_TAG_USAGE_EXPIRE_DATE_TIME;
import static com.google.android.attestation.Constants.KM_TAG_USER_AUTH_TYPE;
import static com.google.android.attestation.Constants.KM_TAG_VENDOR_PATCH_LEVEL;
import static com.google.android.attestation.Constants.UINT32_MAX;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;

/**
 * This data structure contains the key pair's properties themselves, as defined in the Keymaster
 * hardware abstraction layer (HAL). You compare these values to the device's current state or to a
 * set of expected values to verify that a key pair is still valid for use in your app.
 */
@SuppressWarnings("OptionalUsedAsFieldOrParameterType")
public class AuthorizationList {
  /** Specifies the types of user authenticators that may be used to authorize this key. */
  public enum UserAuthType {
    USER_AUTH_TYPE_NONE,
    PASSWORD,
    FINGERPRINT,
    USER_AUTH_TYPE_ANY
  }

  public final Optional<Set<Integer>> purpose;
  public final Optional<Integer> algorithm;
  public final Optional<Integer> keySize;
  public final Optional<Set<Integer>> digest;
  public final Optional<Set<Integer>> padding;
  public final Optional<Integer> ecCurve;
  public final Optional<Long> rsaPublicExponent;
  public final boolean rollbackResistance;
  public final Optional<Instant> activeDateTime;
  public final Optional<Instant> originationExpireDateTime;
  public final Optional<Instant> usageExpireDateTime;
  public final boolean noAuthRequired;
  public final Optional<UserAuthType> userAuthType;
  public final Optional<Duration> authTimeout;
  public final boolean allowWhileOnBody;
  public final boolean trustedUserPresenceRequired;
  public final boolean trustedConfirmationRequired;
  public final boolean unlockedDeviceRequired;
  public final boolean allApplications;
  public final Optional<byte[]> applicationId;
  public final Optional<Instant> creationDateTime;
  public final Optional<Integer> origin;
  public final boolean rollbackResistant;
  public final Optional<RootOfTrust> rootOfTrust;
  public final Optional<Integer> osVersion;
  public final Optional<Integer> osPatchLevel;
  public final Optional<AttestationApplicationId> attestationApplicationId;
  public final Optional<byte[]> attestationApplicationIdBytes;
  public final Optional<byte[]> attestationIdBrand;
  public final Optional<byte[]> attestationIdDevice;
  public final Optional<byte[]> attestationIdProduct;
  public final Optional<byte[]> attestationIdSerial;
  public final Optional<byte[]> attestationIdImei;
  public final Optional<byte[]> attestationIdMeid;
  public final Optional<byte[]> attestationIdManufacturer;
  public final Optional<byte[]> attestationIdModel;
  public final Optional<Integer> vendorPatchLevel;
  public final Optional<Integer> bootPatchLevel;

  private AuthorizationList(ASN1Encodable[] authorizationList, int attestationVersion) {
    Map<Integer, ASN1Primitive> authorizationMap = getAuthorizationMap(authorizationList);
    this.purpose = findOptionalIntegerSetAuthorizationListEntry(authorizationMap, KM_TAG_PURPOSE);
    this.algorithm = findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_ALGORITHM);
    this.keySize = findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_KEY_SIZE);
    this.digest = findOptionalIntegerSetAuthorizationListEntry(authorizationMap, KM_TAG_DIGEST);
    this.padding = findOptionalIntegerSetAuthorizationListEntry(authorizationMap, KM_TAG_PADDING);
    this.ecCurve = findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_EC_CURVE);
    this.rsaPublicExponent =
        findOptionalLongAuthorizationListEntry(authorizationMap, KM_TAG_RSA_PUBLIC_EXPONENT);
    this.rollbackResistance =
        findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_ROLLBACK_RESISTANCE);
    this.activeDateTime =
        findOptionalInstantMillisAuthorizationListEntry(authorizationMap, KM_TAG_ACTIVE_DATE_TIME);
    this.originationExpireDateTime =
        findOptionalInstantMillisAuthorizationListEntry(
            authorizationMap, KM_TAG_ORIGINATION_EXPIRE_DATE_TIME);
    this.usageExpireDateTime =
        findOptionalInstantMillisAuthorizationListEntry(
            authorizationMap, KM_TAG_USAGE_EXPIRE_DATE_TIME);
    this.noAuthRequired =
        findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_NO_AUTH_REQUIRED);
    this.userAuthType = findOptionalUserAuthType(authorizationMap, KM_TAG_USER_AUTH_TYPE);
    this.authTimeout =
        findOptionalDurationSecondsAuthorizationListEntry(authorizationMap, KM_TAG_AUTH_TIMEOUT);
    this.allowWhileOnBody =
        findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_ALLOW_WHILE_ON_BODY);
    this.trustedUserPresenceRequired =
        findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED);
    this.trustedConfirmationRequired =
        findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_TRUSTED_CONFIRMATION_REQUIRED);
    this.unlockedDeviceRequired =
        findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_UNLOCKED_DEVICE_REQUIRED);
    this.allApplications =
        findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_ALL_APPLICATIONS);
    this.applicationId =
        findOptionalByteArrayAuthorizationListEntry(authorizationMap, KM_TAG_APPLICATION_ID);
    this.creationDateTime =
        findOptionalInstantMillisAuthorizationListEntry(
            authorizationMap, KM_TAG_CREATION_DATE_TIME);
    this.origin = findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_ORIGIN);
    this.rollbackResistant =
        findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_ROLLBACK_RESISTANT);
    this.rootOfTrust =
        Optional.ofNullable(
            RootOfTrust.createRootOfTrust(
                (ASN1Sequence) findAuthorizationListEntry(authorizationMap, KM_TAG_ROOT_OF_TRUST),
                attestationVersion));
    this.osVersion = findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_OS_VERSION);
    this.osPatchLevel =
        findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_OS_PATCH_LEVEL);
    this.attestationApplicationId =
        Optional.ofNullable(
            AttestationApplicationId.createAttestationApplicationId(
                (DEROctetString)
                    findAuthorizationListEntry(
                        authorizationMap, KM_TAG_ATTESTATION_APPLICATION_ID)));
    this.attestationApplicationIdBytes =
        findOptionalByteArrayAuthorizationListEntry(
            authorizationMap, KM_TAG_ATTESTATION_APPLICATION_ID);
    this.attestationIdBrand =
        findOptionalByteArrayAuthorizationListEntry(authorizationMap, KM_TAG_ATTESTATION_ID_BRAND);
    this.attestationIdDevice =
        findOptionalByteArrayAuthorizationListEntry(authorizationMap, KM_TAG_ATTESTATION_ID_DEVICE);
    this.attestationIdProduct =
        findOptionalByteArrayAuthorizationListEntry(
            authorizationMap, KM_TAG_ATTESTATION_ID_PRODUCT);
    this.attestationIdSerial =
        findOptionalByteArrayAuthorizationListEntry(authorizationMap, KM_TAG_ATTESTATION_ID_SERIAL);
    this.attestationIdImei =
        findOptionalByteArrayAuthorizationListEntry(authorizationMap, KM_TAG_ATTESTATION_ID_IMEI);
    this.attestationIdMeid =
        findOptionalByteArrayAuthorizationListEntry(authorizationMap, KM_TAG_ATTESTATION_ID_MEID);
    this.attestationIdManufacturer =
        findOptionalByteArrayAuthorizationListEntry(
            authorizationMap, KM_TAG_ATTESTATION_ID_MANUFACTURER);
    this.attestationIdModel =
        findOptionalByteArrayAuthorizationListEntry(authorizationMap, KM_TAG_ATTESTATION_ID_MODEL);
    this.vendorPatchLevel =
        findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_VENDOR_PATCH_LEVEL);
    this.bootPatchLevel =
        findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_BOOT_PATCH_LEVEL);
  }

  static AuthorizationList createAuthorizationList(
      ASN1Encodable[] authorizationList, int attestationVersion) {
    return new AuthorizationList(authorizationList, attestationVersion);
  }

  private static Map<Integer, ASN1Primitive> getAuthorizationMap(
      ASN1Encodable[] authorizationList) {
    Map<Integer, ASN1Primitive> authorizationMap = new HashMap<>();
    for (ASN1Encodable entry : authorizationList) {
      ASN1TaggedObject taggedEntry = (ASN1TaggedObject) entry;
      authorizationMap.put(taggedEntry.getTagNo(), taggedEntry.getObject());
    }
    return authorizationMap;
  }

  private static ASN1Primitive findAuthorizationListEntry(
      Map<Integer, ASN1Primitive> authorizationMap, int tag) {
    return authorizationMap.getOrDefault(tag, null);
  }

  private static Optional<Set<Integer>> findOptionalIntegerSetAuthorizationListEntry(
      Map<Integer, ASN1Primitive> authorizationMap, int tag) {
    ASN1Set asn1Set = (ASN1Set) findAuthorizationListEntry(authorizationMap, tag);
    if (asn1Set == null) {
      return Optional.empty();
    }
    Set<Integer> entrySet = new HashSet<>();
    for (ASN1Encodable value : asn1Set) {
      entrySet.add(ASN1Parsing.getIntegerFromAsn1(value));
    }
    return Optional.of(entrySet);
  }

  private static Optional<Duration> findOptionalDurationSecondsAuthorizationListEntry(
      Map<Integer, ASN1Primitive> authorizationMap, int tag) {
    Optional<Integer> seconds = findOptionalIntegerAuthorizationListEntry(authorizationMap, tag);
    return seconds.map(Duration::ofSeconds);
  }

  private static Optional<Integer> findOptionalIntegerAuthorizationListEntry(
      Map<Integer, ASN1Primitive> authorizationMap, int tag) {
    ASN1Primitive entry = findAuthorizationListEntry(authorizationMap, tag);
    return Optional.ofNullable(entry).map(ASN1Parsing::getIntegerFromAsn1);
  }

  private static Optional<Instant> findOptionalInstantMillisAuthorizationListEntry(
      Map<Integer, ASN1Primitive> authorizationMap, int tag) {
    Optional<Long> millis = findOptionalLongAuthorizationListEntry(authorizationMap, tag);
    return millis.map(Instant::ofEpochMilli);
  }

  private static Optional<Long> findOptionalLongAuthorizationListEntry(
      Map<Integer, ASN1Primitive> authorizationMap, int tag) {
    ASN1Integer longEntry = ((ASN1Integer) findAuthorizationListEntry(authorizationMap, tag));
    return Optional.ofNullable(longEntry).map(value -> value.getValue().longValue());
  }

  private static boolean findBooleanAuthorizationListEntry(
      Map<Integer, ASN1Primitive> authorizationMap, int tag) {
    return null != findAuthorizationListEntry(authorizationMap, tag);
  }

  private static Optional<byte[]> findOptionalByteArrayAuthorizationListEntry(
      Map<Integer, ASN1Primitive> authorizationMap, int tag) {
    ASN1OctetString entry = (ASN1OctetString) findAuthorizationListEntry(authorizationMap, tag);
    return Optional.ofNullable(entry).map(ASN1OctetString::getOctets);
  }

  private static Optional<UserAuthType> findOptionalUserAuthType(
      Map<Integer, ASN1Primitive> authorizationMap, int tag) {
    Optional<Long> userAuthType = findOptionalLongAuthorizationListEntry(authorizationMap, tag);
    return userAuthType.map(AuthorizationList::userAuthTypeToEnum);
  }

  // Visible for testing.
  static UserAuthType userAuthTypeToEnum(long userAuthType) {
    if (userAuthType == 0L) {
      return USER_AUTH_TYPE_NONE;
    } else if (userAuthType == 1L) {
      return PASSWORD;
    } else if (userAuthType == 2L) {
      return FINGERPRINT;
    } else if (userAuthType == UINT32_MAX) {
      return USER_AUTH_TYPE_ANY;
    }
    throw new IllegalArgumentException("Invalid User Auth Type.");
  }
}
