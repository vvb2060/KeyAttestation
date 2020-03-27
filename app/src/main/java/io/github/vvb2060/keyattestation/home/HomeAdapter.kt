package io.github.vvb2060.keyattestation.home

import android.text.TextUtils
import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.attestation.*
import rikka.recyclerview.IdBasedRecyclerViewAdapter

class HomeAdapter(listener: Listener) : IdBasedRecyclerViewAdapter() {

    interface Listener {

        fun onSubtitleDataClick(data: SubtitleData)

        fun onCommonDataClick(data: CommonData)

        fun onSecurityLevelDataClick(data: SecurityLevelData)

        fun onAuthorizationItemDataClick(data: AuthorizationItemData)
    }

    init {
        setHasStableIds(true)
        setListener(listener)
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
        addItem(CommonItemViewHolder.SECURITY_LEVEL_CREATOR, SecurityLevelData(
                R.string.attestation,
                R.string.attestation_version_description,
                R.string.security_level_description,
                attestation.attestationVersion,
                attestation.attestationSecurityLevel), id++)

        addItem(CommonItemViewHolder.SECURITY_LEVEL_CREATOR, SecurityLevelData(
                R.string.keymaster,
                R.string.keymaster_version_description,
                R.string.security_level_description,
                attestation.keymasterVersion,
                attestation.keymasterSecurityLevel), id++)

        addItem(CommonItemViewHolder.COMMON_CREATOR, CommonData(
                R.string.attestation_challenge,
                R.string.attestation_challenge_description,
                attestation.attestationChallengeOrBase64), id++)

        addItem(CommonItemViewHolder.COMMON_CREATOR, CommonData(
                R.string.unique_id,
                R.string.unique_id_description,
                attestation.uniqueIdBase64), id++)

        id = ID_AUTHORIZATION_LIST_START
        addItem(SubtitleViewHolder.CREATOR, SubtitleData(
                R.string.authorization_list,
                R.string.authorization_list_description), id++)

        var tee = attestation.teeEnforced.purposes != null
        val purposes = attestation.teeEnforced.purposesDisplayName ?: attestation.softwareEnforced.purposesDisplayName
        addItem(CommonItemViewHolder.AUTHORIZATION_ITEM_CREATOR, AuthorizationItemData(
                R.string.purposes,
                R.string.purposes_description,
                purposes,
                tee), id++)

        tee = attestation.teeEnforced.purposes != null
        val algorithm = attestation.teeEnforced.algorithmDisplayName ?: attestation.softwareEnforced.algorithmDisplayName
        addItem(CommonItemViewHolder.AUTHORIZATION_ITEM_CREATOR, AuthorizationItemData(
                R.string.algorithm,
                R.string.algorithm_description,
                algorithm,
                tee), id++)

        tee = attestation.teeEnforced.keySize != null
        val keySize = attestation.teeEnforced.keySize ?: attestation.softwareEnforced.keySize
        addItem(CommonItemViewHolder.AUTHORIZATION_ITEM_CREATOR, AuthorizationItemData(
                R.string.key_size,
                R.string.key_size_description,
                keySize.toString(),
                tee), id++)

        tee = attestation.teeEnforced.digests != null
        val digests = attestation.teeEnforced.digestsDisplayName ?: attestation.softwareEnforced.digestsDisplayName
        addItem(CommonItemViewHolder.AUTHORIZATION_ITEM_CREATOR, AuthorizationItemData(
                R.string.digests,
                R.string.digests_description,
                digests,
                tee), id++)

        tee = attestation.teeEnforced.paddingModesAsStrings != null
        val padding = attestation.teeEnforced.paddingModesAsStrings ?: attestation.softwareEnforced.paddingModesAsStrings
        addItem(CommonItemViewHolder.AUTHORIZATION_ITEM_CREATOR, AuthorizationItemData(
                R.string.padding,
                R.string.padding_description,
                TextUtils.join(", ", padding),
                tee), id++)

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
            false
        } else {
            (getItemId(position + 1) / 1000 - id / 1000) > 0
        }
    }

    companion object {

        private const val ID_BOOT_STATE = 1L
        private const val ID_BOOT_STATE_UNTRUSTWORTHY = 2L
        private const val ID_DESCRIPTION_START = 3000L
        private const val ID_AUTHORIZATION_LIST_START = 4000L
        private const val ID_TEE_ENFORCED_START = 5000L
    }
}
