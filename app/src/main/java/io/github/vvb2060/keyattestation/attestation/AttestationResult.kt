package io.github.vvb2060.keyattestation.attestation

import android.text.TextUtils
import com.google.common.base.CharMatcher
import com.google.common.io.BaseEncoding

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
                0 -> "ENCRYPT"
                1 -> "DECRYPT"
                2 -> "SIGN"
                3 -> "VERIFY"
                4 -> "DERIVE_KEY"
                5 -> "WRAP_KEY"
                else -> "unknown ($i)"
            })
        }
        return TextUtils.join(", ", texts)
    }

val AuthorizationList.algorithmDisplayName: String?
    get() {
        return when (algorithm) {
            1 -> "RSA"
            3 -> "EC"
            32 -> "AES"
            128 -> "HMAC"
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
                0 -> "NONE"
                1 -> "MD5"
                2 -> "SHA1"
                3 -> "SHA_2_224"
                4 -> "SHA_2_256"
                5 -> "SHA_2_384"
                6 -> "SHA_2_512"
                else -> "unknown ($algorithm)"
            })
        }
        return TextUtils.join(", ", texts)
    }