package io.github.vvb2060.keyattestation.lang

import io.github.vvb2060.keyattestation.R

class AttestationException(var code: Int, cause: Throwable?) : RuntimeException(cause) {

    companion object {
        const val CODE_UNKNOWN = -1
        const val CODE_NOT_SUPPORT = 0
        const val CODE_CERT_NOT_TRUSTED = 1
        const val CODE_CANT_PARSE_ATTESTATION_RECORD = 2
    }

    val titleResId: Int
        get() {
            return when (code) {
                CODE_NOT_SUPPORT -> {
                    R.string.error_not_support
                }
                CODE_CERT_NOT_TRUSTED -> {
                    R.string.error_cert_not_trusted
                }
                CODE_CANT_PARSE_ATTESTATION_RECORD -> {
                    R.string.error_cant_parse_record
                }
                else -> {
                    R.string.error_unknown
                }
            }
        }

    val descriptionResId: Int
        get() {
            return when (code) {
                CODE_NOT_SUPPORT -> {
                    R.string.error_not_support_summary
                }
                else -> {
                    0
                }
            }
        }
}