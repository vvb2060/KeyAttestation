package io.github.vvb2060.keyattestation.home

import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.attestation.Attestation
import io.github.vvb2060.keyattestation.attestation.AttestationResult
import rikka.recyclerview.IdBasedRecyclerViewAdapter

class HomeAdapter : IdBasedRecyclerViewAdapter() {

    init {
        setHasStableIds(true)
    }

    fun updateData(attestationResult: AttestationResult) {
        val attestation = attestationResult.attestation
        val locked = attestation.teeEnforced?.rootOfTrust?.isDeviceLocked
        val isGoogleRootCertificate = attestationResult.isGoogleRootCertificate
        val isSoftware = attestation.attestationSecurityLevel == Attestation.KM_SECURITY_LEVEL_SOFTWARE
        val trustworthy = isGoogleRootCertificate && !isSoftware

        clear()
        if (locked != null && !trustworthy) {
            addItem(BootStateUntrustworthyViewHolder.CREATOR, attestationResult, ID_BOOT_STATE_UNTRUSTWORTHY)
        }
        addItem(BootStateViewHolder.CREATOR, attestationResult, ID_BOOT_STATE)

        var id = ID_DESCRIPTION_START
        addItem(CommonItemViewHolder.COMMON_CREATOR, R.string.attestation_version to attestation.attestationVersion.toString(), id++)
        addItem(CommonItemViewHolder.SECURITY_LEVEL_CREATOR, R.string.attestation_security_level to attestation.attestationSecurityLevel, id++)
        addItem(CommonItemViewHolder.COMMON_CREATOR, R.string.keymaster_version to attestation.keymasterVersion.toString(), id++)
        addItem(CommonItemViewHolder.SECURITY_LEVEL_CREATOR, R.string.keymaster_security_level to attestation.keymasterSecurityLevel, id++)
        addItem(CommonItemViewHolder.COMMON_CREATOR, R.string.attestation_challenge to attestation.attestationChallengeOrBase64, id++)

        notifyDataSetChanged()
    }

    fun allowFrameAt(position: Int): Boolean {
        val id = getItemId(position)
        return id >= ID_DESCRIPTION_START
    }

    fun shouldCommitFrameAt(position: Int): Boolean {
        val id = getItemId(position)
        if (position == itemCount - 1) {
            return true
        }
        return if (id < ID_DESCRIPTION_START) {
            true
        } else {
            (getItemId(position + 1) / 1000 - id / 1000) > 0
        }
    }

    companion object {

        private const val ID_BOOT_STATE = 1L
        private const val ID_BOOT_STATE_UNTRUSTWORTHY = 2L
        private const val ID_DESCRIPTION_START = 3000L
        private const val ID_SW_ENFORCED_START = 4000L
        private const val ID_TEE_ENFORCED_START = 5000L
    }
}
