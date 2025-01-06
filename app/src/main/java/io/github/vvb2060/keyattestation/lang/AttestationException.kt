package io.github.vvb2060.keyattestation.lang

import io.github.vvb2060.keyattestation.R

class AttestationException(code: Int, cause: Throwable) : RuntimeException(cause) {

    companion object {
        const val CODE_UNKNOWN = -1
        const val CODE_UNAVAILABLE = 0
        const val CODE_CANT_PARSE_CERT = 2
        const val CODE_STRONGBOX_UNAVAILABLE = 3
        const val CODE_DEVICEIDS_UNAVAILABLE = 4
        const val CODE_OUT_OF_KEYS = 5
        const val CODE_OUT_OF_KEYS_TRANSIENT = 6
        const val CODE_UNAVAILABLE_TRANSIENT = 7
        const val CODE_KEYS_NOT_PROVISIONED = 8
        const val CODE_RKP = 9
    }

    val titleResId: Int = when (code) {
        CODE_UNAVAILABLE -> R.string.error_unavailable
        CODE_CANT_PARSE_CERT -> R.string.error_cant_parse_cert
        CODE_STRONGBOX_UNAVAILABLE -> R.string.error_strongbox_unavailable
        CODE_DEVICEIDS_UNAVAILABLE -> R.string.error_deviceids_unavailable
        CODE_OUT_OF_KEYS -> R.string.error_out_of_keys
        CODE_OUT_OF_KEYS_TRANSIENT -> R.string.error_out_of_keys_transient
        CODE_UNAVAILABLE_TRANSIENT -> R.string.error_unavailable_transient
        CODE_KEYS_NOT_PROVISIONED -> R.string.error_keys_not_provisioned
        CODE_RKP -> R.string.error_remote_key_provisioning
        else -> R.string.error_unknown
    }

    val descriptionResId: Int = when (code) {
        CODE_UNAVAILABLE -> R.string.error_unavailable_summary
        CODE_CANT_PARSE_CERT -> R.string.error_cant_parse_cert_summary
        CODE_STRONGBOX_UNAVAILABLE -> R.string.error_strongbox_unavailable_summary
        CODE_DEVICEIDS_UNAVAILABLE -> R.string.error_deviceids_unavailable_summary
        CODE_OUT_OF_KEYS -> R.string.error_out_of_keys_summary
        CODE_OUT_OF_KEYS_TRANSIENT -> R.string.error_out_of_keys_transient_summary
        CODE_UNAVAILABLE_TRANSIENT -> R.string.error_unavailable_transient_summary
        CODE_KEYS_NOT_PROVISIONED -> R.string.error_keys_not_provisioned_summary
        CODE_RKP -> R.string.error_remote_key_provisioning_summary
        else -> R.string.error_unknown
    }

    override fun fillInStackTrace() = this
}
