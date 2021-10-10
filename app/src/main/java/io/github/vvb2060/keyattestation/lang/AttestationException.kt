package io.github.vvb2060.keyattestation.lang

import io.github.vvb2060.keyattestation.R

class AttestationException(val code: Int, cause: Throwable?) : RuntimeException(cause) {

    companion object {
        const val CODE_UNKNOWN = -1
        const val CODE_NOT_SUPPORT = 0
        const val CODE_CERT_NOT_TRUSTED = 1
        const val CODE_CANT_PARSE_ATTESTATION_RECORD = 2
        const val CODE_STRONGBOX_UNAVAILABLE = 3
        const val CODE_DEVICEIDS_UNAVAILABLE = 4
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
                CODE_STRONGBOX_UNAVAILABLE -> {
                    R.string.error_strongbox_unavailable
                }
                CODE_DEVICEIDS_UNAVAILABLE -> {
                    R.string.error_unable_attest_deviceids
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
                CODE_CERT_NOT_TRUSTED -> {
                    R.string.error_cert_not_trusted
                }
                CODE_STRONGBOX_UNAVAILABLE -> {
                    R.string.error_strongbox_unavailable_summary
                }
                CODE_DEVICEIDS_UNAVAILABLE -> {
                    R.string.error_unable_attest_deviceids_summary
                }
                else -> {
                    R.string.error_unknown
                }
            }
        }
}
