package io.github.vvb2060.keyattestation.home

import androidx.annotation.StringRes
import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.attestation.Attestation

abstract class Data {

    abstract val title: Int
        @StringRes get

    abstract val description: Int
        @StringRes get

    companion object {

        fun createAttestationLevel(attestation: Attestation) = SecurityLevelData(
                R.string.attestation,
                R.string.attestation_version_description,
                R.string.security_level_description,
                attestation.attestationVersion,
                attestation.attestationSecurityLevel)

        fun createKeymasterLevel(attestation: Attestation) = SecurityLevelData(
                R.string.keymaster,
                R.string.keymaster_version_description,
                R.string.security_level_description,
                attestation.keymasterVersion,
                attestation.keymasterSecurityLevel)

        fun createAttestationChallenge(attestation: Attestation) = CommonData(
                R.string.attestation_challenge,
                R.string.attestation_challenge_description,
                attestation.attestationChallengeOrBase64)

        fun createUniqueId(attestation: Attestation) = CommonData(
                R.string.unique_id,
                R.string.unique_id_description,
                attestation.uniqueIdBase64)
    }
}

data class CommonData(override val title: Int, override val description: Int, val data: String?) : Data()

data class SecurityLevelData(override val title: Int, override val description: Int, val securityLevelDescription: Int, val version: Int, val securityLevel: Int) : Data()