package io.github.vvb2060.keyattestation.home

import android.util.Base64
import android.util.Pair
import com.google.common.io.BaseEncoding
import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.attestation.*
import io.github.vvb2060.keyattestation.lang.AttestationException
import io.github.vvb2060.keyattestation.lang.AttestationException.Companion.CODE_RKP
import io.github.vvb2060.keyattestation.repository.AttestationData
import io.github.vvb2060.keyattestation.repository.BaseData
import io.github.vvb2060.keyattestation.repository.RemoteProvisioningData
import rikka.recyclerview.IdBasedRecyclerViewAdapter

class HomeAdapter(listener: Listener) : IdBasedRecyclerViewAdapter() {

    interface Listener {
        fun onCommonDataClick(data: Data)
        fun onAttestationInfoClick(data: Attestation)
        fun onRkpHostnameClick(data: String)
    }

    init {
        setHasStableIds(true)
        setListener(listener)
    }

    fun updateData(baseData: BaseData) {
        clear()
        when (baseData.status) {
            RootPublicKey.Status.NULL -> {
                addItem(HeaderViewHolder.CREATOR, HeaderData(
                        R.string.error_remote_key_provisioning,
                        0,
                        R.drawable.ic_error_outline_24,
                        rikka.material.R.attr.colorInactive), ID_CERT_STATUS)
            }
            RootPublicKey.Status.FAILED -> {
                addItem(HeaderViewHolder.CREATOR, HeaderData(
                        R.string.cert_chain_not_trusted,
                        R.string.cert_chain_not_trusted_summary,
                        R.drawable.ic_error_outline_24,
                        rikka.material.R.attr.colorAlert), ID_CERT_STATUS)
            }
            RootPublicKey.Status.UNKNOWN -> {
                addItem(HeaderViewHolder.CREATOR, HeaderData(
                        R.string.unknown_root_cert,
                        R.string.unknown_root_cert_summary,
                        R.drawable.ic_error_outline_24,
                        rikka.material.R.attr.colorWarning), ID_CERT_STATUS)
            }
            RootPublicKey.Status.AOSP -> {
                addItem(HeaderViewHolder.CREATOR, HeaderData(
                        R.string.aosp_root_cert,
                        R.string.aosp_root_cert_summary,
                        R.drawable.ic_error_outline_24,
                        rikka.material.R.attr.colorWarning), ID_CERT_STATUS)
            }
            RootPublicKey.Status.GOOGLE -> {
                addItem(HeaderViewHolder.CREATOR, HeaderData(
                        R.string.google_root_cert,
                        R.string.google_root_cert_summary,
                        R.drawable.ic_trustworthy_24,
                        rikka.material.R.attr.colorSafe), ID_CERT_STATUS)
            }
            RootPublicKey.Status.GOOGLE_RKP -> {
                addItem(HeaderViewHolder.CREATOR, HeaderData(
                        R.string.google_root_cert_rkp,
                        R.string.google_root_cert_rkp_summary,
                        R.drawable.ic_trustworthy_24,
                        rikka.material.R.attr.colorSafe), ID_CERT_STATUS)
            }
            RootPublicKey.Status.KNOX -> {
                addItem(HeaderViewHolder.CREATOR, HeaderData(
                        R.string.knox_root_cert,
                        R.string.knox_root_cert_summary,
                        R.drawable.ic_trustworthy_24,
                        rikka.material.R.attr.colorSafe), ID_CERT_STATUS)
            }
            RootPublicKey.Status.OEM -> {
                addItem(HeaderViewHolder.CREATOR, HeaderData(
                        R.string.oem_root_cert,
                        R.string.oem_root_cert_summary,
                        R.drawable.ic_trustworthy_24,
                        rikka.material.R.attr.colorSafe), ID_CERT_STATUS)
            }
        }

        var id = ID_CERT_INFO_START
        addItem(SubtitleViewHolder.CREATOR, CommonData(
                R.string.cert_chain,
                R.string.cert_chain_description), id++)
        baseData.certs.forEach { certInfo ->
            addItem(CommonItemViewHolder.CERT_INFO_CREATOR, certInfo, id++)
        }

        when (baseData) {
            is AttestationData -> updateData(baseData)
            is RemoteProvisioningData -> updateData(baseData)
        }

        notifyDataSetChanged()
    }

    private fun updateData(attestationData: AttestationData) {
        addItemAt(1, BootStateViewHolder.CREATOR, attestationData, ID_BOOT_STATUS)

        var id = ID_DESCRIPTION_START
        val attestation = attestationData.showAttestation ?: return
        addItem(CommonItemViewHolder.SECURITY_LEVEL_CREATOR, SecurityLevelData(
                R.string.attestation,
                R.string.attestation_version_description,
                R.string.security_level_description,
                Attestation.attestationVersionToString(attestation.attestationVersion),
                attestation.attestationSecurityLevel), id++)

        addItem(CommonItemViewHolder.SECURITY_LEVEL_CREATOR, SecurityLevelData(
                R.string.keymaster,
                R.string.keymaster_version_description,
                R.string.security_level_description,
                Attestation.keymasterVersionToString(attestation.keymasterVersion),
                attestation.keymasterSecurityLevel), id++)

        addItem(CommonItemViewHolder.COMMON_CREATOR, CommonData(
                R.string.attestation_challenge,
                R.string.attestation_challenge_description,
                attestation.attestationChallenge?.let {
                    val stringChallenge = String(it)
                    if (stringChallenge.toByteArray().contentEquals(it)) stringChallenge
                    else Base64.encodeToString(it, 0) + " (base64)"
                }), id++)

        addItem(CommonItemViewHolder.COMMON_CREATOR, CommonData(
                R.string.unique_id,
                R.string.unique_id_description,
                attestation.uniqueId?.let { BaseEncoding.base16().lowerCase().encode(it) }), id)

        id = ID_AUTHORIZATION_LIST_START
        addItem(SubtitleViewHolder.CREATOR, CommonData(
                R.string.authorization_list,
                R.string.authorization_list_description), id++)

        val tee = createAuthorizationItems(attestation.teeEnforced)
        val sw = createAuthorizationItems(attestation.softwareEnforced)
        for (i in tee.indices) {
            val h = tee[i]
            val s = sw[i]
            if (h == null && s == null) {
                continue
            }

            addItem(CommonItemViewHolder.AUTHORIZATION_ITEM_CREATOR, AuthorizationItemData(
                    authorizationItemTitles[i],
                    authorizationItemDescriptions[i],
                    h, s), id++)

            if (h != null && s != null) {
                addItem(CommonItemViewHolder.AUTHORIZATION_ITEM_CREATOR, AuthorizationItemData(
                        authorizationItemTitles[i],
                        authorizationItemDescriptions[i],
                        s, false), id++)
            }
        }

        if (attestation is KnoxAttestation) {
            id = ID_KNOX_START
            addItem(SubtitleViewHolder.CREATOR, CommonData(
                    R.string.knox,
                    R.string.knox_description), id++)

            addItem(CommonItemViewHolder.COMMON_CREATOR, CommonData(
                    R.string.knox_challenge,
                    R.string.knox_challenge_description,
                    attestation.knoxChallenge), id++)

            addItem(CommonItemViewHolder.COMMON_CREATOR, CommonData(
                R.string.knox_id_attest,
                R.string.knox_id_attest_description,
                attestation.idAttest), id++)

            addItem(CommonItemViewHolder.COMMON_CREATOR, CommonData(
                    R.string.knox_integrity,
                    R.string.knox_integrity_description,
                    attestation.knoxIntegrity.toString()), id++)

            addItem(CommonItemViewHolder.COMMON_CREATOR, CommonData(
                    R.string.knox_record_hash,
                    R.string.knox_record_hash_description,
                    BaseEncoding.base16().lowerCase().encode(attestation.recordHash)), id++)
        }
    }

    private fun updateData(rkpData: RemoteProvisioningData) {
        if (rkpData.status == RootPublicKey.Status.NULL) {
            removeItemAt(1)
            var e = AttestationException(CODE_RKP, rkpData.error)
            addItemAt(1, ErrorViewHolder.CREATOR, e, ID_CERT_INFO_START)
        }

        if (rkpData.rkpHostname != null) {
            addItem(CommonItemViewHolder.HOSTNAME_CREATOR, StringData(
                R.string.rkp_hostname,
                rkpData.rkpHostname), ID_RKP_HOSTNAME)
        }

        var id = ID_DESCRIPTION_START
        var hardware = rkpData.hardwareInfo
        addItem(SubtitleViewHolder.CREATOR, CommonData(
            R.string.rpc_hardware_info,
            R.string.rpc_hardware_info_description), id++)

        addItem(CommonItemViewHolder.COMMON_CREATOR, CommonData(
            R.string.rpc_version_number,
            R.string.rpc_version_number_description,
            hardware.versionNumber.toString()), id++)

        addItem(CommonItemViewHolder.COMMON_CREATOR, CommonData(
            R.string.rpc_author_name,
            R.string.rpc_author_name_description,
            hardware.rpcAuthorName.toString()), id++)

        addItem(CommonItemViewHolder.COMMON_CREATOR, CommonData(
            R.string.rpc_unique_id,
            R.string.rpc_unique_id_description,
            hardware.uniqueId), id++)

        id = ID_AUTHORIZATION_LIST_START
        addItem(SubtitleViewHolder.CREATOR, CommonData(
            R.string.rkp_device_info,
            R.string.rkp_device_info_description), id++)

        rkpData.deviceInfo.forEach { key, value ->
            addItem(CommonItemViewHolder.SIMPLE_CREATOR, Pair(key, value), id++)
        }
    }

    fun updateData(e: AttestationException) {
        clear()
        addItem(HeaderViewHolder.CREATOR, HeaderData(
                e.titleResId,
                0,
                R.drawable.ic_error_outline_24,
                rikka.material.R.attr.colorInactive), ID_ERROR)

        addItem(ErrorViewHolder.CREATOR, e, ID_ERROR_MESSAGE)
        notifyDataSetChanged()
    }

    fun allowFrameAt(position: Int): Boolean {
        if (position < 0) return false
        val id = getItemId(position)
        return id >= ID_CERT_INFO_START
    }

    fun shouldCommitFrameAt(position: Int): Boolean {
        if (position < 0) return false
        val id = getItemId(position)
        if (position == itemCount - 1) {
            return true
        }
        return if (id < ID_CERT_INFO_START) {
            false
        } else {
            (getItemId(position + 1) / 1000 - id / 1000) > 0
        }
    }

    companion object {

        private const val ID_ERROR = 0L
        private const val ID_CERT_STATUS = 1L
        private const val ID_BOOT_STATUS = 2L
        private const val ID_CERT_INFO_START = 1000L
        private const val ID_RKP_HOSTNAME = 2000L
        private const val ID_DESCRIPTION_START = 3000L
        private const val ID_AUTHORIZATION_LIST_START = 4000L
        private const val ID_KNOX_START = 5000L
        private const val ID_ERROR_MESSAGE = 100000L

        private fun createAuthorizationItems(list: AuthorizationList): Array<String?> {
            return arrayOf(
                    list.purposes?.let { AuthorizationList.purposesToString(it) },
                    list.algorithm?.let { AuthorizationList.algorithmToString(it) },
                    list.keySize?.toString(),
                    list.digests?.let { AuthorizationList.digestsToString(it) },
                    list.paddingModes?.let { AuthorizationList.paddingModesToString(it) },
                    list.ecCurve?.let { AuthorizationList.ecCurveAsString(it) },
                    list.rsaPublicExponent?.toString(),
                    list.mgfDigests?.let { AuthorizationList.digestsToString(it) },
                    list.rollbackResistance?.toString(),
                    list.earlyBootOnly?.toString(),
                    list.activeDateTime?.let { AuthorizationList.formatDate(it) },
                    list.originationExpireDateTime?.let { AuthorizationList.formatDate(it) },
                    list.usageExpireDateTime?.let { AuthorizationList.formatDate(it) },
                    list.usageCountLimit?.toString(),
                    list.noAuthRequired?.toString(),
                    list.userAuthType?.let { AuthorizationList.userAuthTypeToString(it) },
                    list.authTimeout?.toString(),
                    list.allowWhileOnBody?.toString(),
                    list.trustedUserPresenceReq?.toString(),
                    list.trustedConfirmationReq?.toString(),
                    list.unlockedDeviceReq?.toString(),
                    list.allApplications?.toString(),
                    list.applicationId,
                    list.creationDateTime?.let { AuthorizationList.formatDate(it) },
                    list.origin?.let { AuthorizationList.originToString(it) },
                    list.rollbackResistant?.toString(),
                    list.rootOfTrust?.toString(),
                    list.osVersion?.toString(),
                    list.osPatchLevel?.toString(),
                    list.attestationApplicationId?.toString()?.trim(),
                    list.brand,
                    list.device,
                    list.product,
                    list.serialNumber,
                    list.imei,
                    list.secondImei,
                    list.meid,
                    list.manufacturer,
                    list.model,
                    list.vendorPatchLevel?.toString(),
                    list.bootPatchLevel?.toString(),
                    list.deviceUniqueAttestation?.toString(),
                    list.identityCredentialKey?.toString(),
                    list.moduleHash?.let { BaseEncoding.base16().lowerCase().encode(it) },
            )
        }

        private val authorizationItemTitles = arrayOf(
                R.string.authorization_list_purpose,
                R.string.authorization_list_algorithm,
                R.string.authorization_list_keySize,
                R.string.authorization_list_digest,
                R.string.authorization_list_padding,
                R.string.authorization_list_ecCurve,
                R.string.authorization_list_rsaPublicExponent,
                R.string.authorization_list_mgfDigest,
                R.string.authorization_list_rollbackResistance,
                R.string.authorization_list_earlyBootOnly,
                R.string.authorization_list_activeDateTime,
                R.string.authorization_list_originationExpireDateTime,
                R.string.authorization_list_usageExpireDateTime,
                R.string.authorization_list_usageCountLimit,
                R.string.authorization_list_noAuthRequired,
                R.string.authorization_list_userAuthType,
                R.string.authorization_list_authTimeout,
                R.string.authorization_list_allowWhileOnBody,
                R.string.authorization_list_trustedUserPresenceRequired,
                R.string.authorization_list_trustedConfirmationRequired,
                R.string.authorization_list_unlockedDeviceRequired,
                R.string.authorization_list_allApplications,
                R.string.authorization_list_applicationId,
                R.string.authorization_list_creationDateTime,
                R.string.authorization_list_origin,
                R.string.authorization_list_rollbackResistant,
                R.string.authorization_list_rootOfTrust,
                R.string.authorization_list_osVersion,
                R.string.authorization_list_osPatchLevel,
                R.string.authorization_list_attestationApplicationId,
                R.string.authorization_list_attestationIdBrand,
                R.string.authorization_list_attestationIdDevice,
                R.string.authorization_list_attestationIdProduct,
                R.string.authorization_list_attestationIdSerial,
                R.string.authorization_list_attestationIdImei,
                R.string.authorization_list_attestationIdSecondImei,
                R.string.authorization_list_attestationIdMeid,
                R.string.authorization_list_attestationIdManufacturer,
                R.string.authorization_list_attestationIdModel,
                R.string.authorization_list_vendorPatchLevel,
                R.string.authorization_list_bootPatchLevel,
                R.string.authorization_list_deviceUniqueAttestation,
                R.string.authorization_list_identityCredentialKey,
                R.string.authorization_list_moduleHash,
        )

        private val authorizationItemDescriptions = arrayOf(
                R.string.authorization_list_purpose_description,
                R.string.authorization_list_algorithm_description,
                R.string.authorization_list_keySize_description,
                R.string.authorization_list_digest_description,
                R.string.authorization_list_padding_description,
                R.string.authorization_list_ecCurve_description,
                R.string.authorization_list_rsaPublicExponent_description,
                R.string.authorization_list_mgfDigest_description,
                R.string.authorization_list_rollbackResistance_description,
                R.string.authorization_list_earlyBootOnly_description,
                R.string.authorization_list_activeDateTime_description,
                R.string.authorization_list_originationExpireDateTime_description,
                R.string.authorization_list_usageExpireDateTime_description,
                R.string.authorization_list_usageCountLimit_description,
                R.string.authorization_list_noAuthRequired_description,
                R.string.authorization_list_userAuthType_description,
                R.string.authorization_list_authTimeout_description,
                R.string.authorization_list_allowWhileOnBody_description,
                R.string.authorization_list_trustedUserPresenceRequired_description,
                R.string.authorization_list_trustedConfirmationRequired_description,
                R.string.authorization_list_unlockedDeviceRequired_description,
                R.string.authorization_list_allApplications_description,
                R.string.authorization_list_applicationId_description,
                R.string.authorization_list_creationDateTime_description,
                R.string.authorization_list_origin_description,
                R.string.authorization_list_rollbackResistant_description,
                R.string.authorization_list_rootOfTrust_description,
                R.string.authorization_list_osVersion_description,
                R.string.authorization_list_osPatchLevel_description,
                R.string.authorization_list_attestationApplicationId_description,
                R.string.authorization_list_attestationIdBrand_description,
                R.string.authorization_list_attestationIdDevice_description,
                R.string.authorization_list_attestationIdProduct_description,
                R.string.authorization_list_attestationIdSerial_description,
                R.string.authorization_list_attestationIdImei_description,
                R.string.authorization_list_attestationIdSecondImei_description,
                R.string.authorization_list_attestationIdMeid_description,
                R.string.authorization_list_attestationIdManufacturer_description,
                R.string.authorization_list_attestationIdModel_description,
                R.string.authorization_list_vendorPatchLevel_description,
                R.string.authorization_list_bootPatchLevel_description,
                R.string.authorization_list_deviceUniqueAttestation_description,
                R.string.authorization_list_identityCredentialKey_description,
                R.string.authorization_list_moduleHash_description,
        )
    }
}
