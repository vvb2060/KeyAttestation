package io.github.vvb2060.keyattestation.attestation

import android.text.TextUtils
import com.google.common.base.CharMatcher
import com.google.common.collect.Lists
import com.google.common.io.BaseEncoding
import io.github.vvb2060.keyattestation.attestation.AuthorizationList.*

data class AttestationResult(val attestation: Attestation, val isGoogleRootCertificate: Boolean)

val Attestation.attestationChallengeOrBase64: String?
    get() {
        val stringChallenge = String(attestationChallenge)
        return if (CharMatcher.ascii().matchesAllOf(stringChallenge)) {
            stringChallenge
        } else {
            BaseEncoding.base64().encode(attestationChallenge) + " (base64)"
        }
    }

val Attestation.uniqueIdBase64: String?
    get() {
        return if (uniqueId != null) {
            BaseEncoding.base64().encode(uniqueId)
        } else null
    }

val AuthorizationList.purposesDisplayName: String?
    get() {
        if (purposes == null)
            return null
        val texts = ArrayList<String>()
        for (i in purposes) {
            texts.add(when (i) {
                KM_PURPOSE_ENCRYPT -> "ENCRYPT"
                KM_PURPOSE_DECRYPT -> "DECRYPT"
                KM_PURPOSE_SIGN -> "SIGN"
                KM_PURPOSE_VERIFY -> "VERIFY"
                4 -> "DERIVE"
                KM_PURPOSE_WRAP -> "WRAP"
                else -> "unknown ($i)"
            })
        }
        return TextUtils.join(", ", texts)
    }

val AuthorizationList.algorithmDisplayName: String?
    get() {
        return when (algorithm) {
            KM_ALGORITHM_RSA -> "RSA"
            KM_ALGORITHM_EC -> "EC"
            KM_ALGORITHM_AES -> "AES"
            KM_ALGORITHM_3DES -> "3DES"
            KM_ALGORITHM_HMAC -> "HMAC"
            null -> null
            else -> "unknown ($algorithm)"
        }
    }

val AuthorizationList.digestsDisplayName: String?
    get() {
        if (digests == null)
            return null
        val texts = ArrayList<String>()
        for (i in digests) {
            texts.add(when (i) {
                KM_DIGEST_NONE -> "NONE"
                KM_DIGEST_MD5 -> "MD5"
                KM_DIGEST_SHA1 -> "SHA1"
                KM_DIGEST_SHA_2_224 -> "SHA224"
                KM_DIGEST_SHA_2_256 -> "SHA256"
                KM_DIGEST_SHA_2_384 -> "SHA384"
                KM_DIGEST_SHA_2_512 -> "SHA512"
                else -> "unknown ($i)"
            })
        }
        return TextUtils.join(", ", texts)
    }

val AuthorizationList.paddingDisplayName: String?
    get() {
        if (paddingModes == null)
            return null
        val texts = ArrayList<String>()
        for (i in paddingModes) {
            texts.add(when (i) {
                KM_PAD_NONE -> "NONE"
                KM_PAD_RSA_OAEP -> "OAEP"
                KM_PAD_RSA_PSS -> "PSS"
                KM_PAD_RSA_PKCS1_1_5_ENCRYPT -> "PKCS1 ENCRYPT"
                KM_PAD_RSA_PKCS1_1_5_SIGN -> "PKCS1 SIGN"
                KM_PAD_PKCS7 -> "PKCS7"
                else -> "unknown ($i)"
            })
        }
        return TextUtils.join(", ", texts)
    }

val AuthorizationList.ecCurveDisplayName: String?
    get() {
        return when (ecCurve) {
            KM_EC_CURVE_P224 -> "secp224r1"
            KM_EC_CURVE_P256 -> "secp256r1"
            KM_EC_CURVE_P384 -> "secp384r1"
            KM_EC_CURVE_P521 -> "secp521r1"
            null -> null
            else -> "unknown ($ecCurve)"
        }
    }

val AuthorizationList.userAuthDisplayName: String?
    get() {
        if (userAuthType == null)
            return null
        val types: MutableList<String> = Lists.newArrayList()
        if (userAuthType and HW_AUTH_BIOMETRIC != 0) types.add("Biometric")
        if (userAuthType and HW_AUTH_PASSWORD != 0) types.add("Password")
        return TextUtils.join(", ", types)
    }