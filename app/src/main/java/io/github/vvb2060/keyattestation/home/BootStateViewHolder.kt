package io.github.vvb2060.keyattestation.home

import android.content.res.ColorStateList
import android.view.View
import androidx.core.view.isVisible
import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.attestation.Attestation
import io.github.vvb2060.keyattestation.attestation.AttestationResult
import io.github.vvb2060.keyattestation.attestation.RootOfTrust
import io.github.vvb2060.keyattestation.databinding.HomeHeaderBinding
import rikka.core.res.resolveColor
import rikka.recyclerview.BaseViewHolder.Creator

class BootStateViewHolder(itemView: View, binding: HomeHeaderBinding) :
        HomeViewHolder<AttestationResult, HomeHeaderBinding>(itemView, binding) {

    companion object {

        val CREATOR = Creator<AttestationResult> { inflater, parent ->
            val binding = HomeHeaderBinding.inflate(inflater, parent, false)
            BootStateViewHolder(binding.root, binding)
        }
    }

    override fun onBind() {
        val context = itemView.context

        val attestation = data.attestation
        val rootOfTrust = attestation.teeEnforced?.rootOfTrust
        val locked = rootOfTrust?.isDeviceLocked
        val bootUnverified = rootOfTrust?.verifiedBootState != RootOfTrust.KM_VERIFIED_BOOT_VERIFIED

        val titleRes: Int
        val summaryRes: Int
        val iconRes: Int
        val colorAttrRes: Int

        if (locked == null) {
            titleRes = R.string.bootloader_unknown
            summaryRes = if (attestation.attestationSecurityLevel == Attestation.KM_SECURITY_LEVEL_SOFTWARE) R.string.bootloader_unknown_summary_software_attestation else 0
            iconRes = R.drawable.ic_boot_unknown_24
            colorAttrRes = rikka.material.R.attr.colorInactive
        } else if (!locked) {
            titleRes = R.string.bootloader_unlocked
            summaryRes = 0
            iconRes = R.drawable.ic_boot_unlocked_24
            colorAttrRes = rikka.material.R.attr.colorWarning
        } else if (bootUnverified) {
            titleRes = R.string.bootloader_locked
            summaryRes = R.string.root_of_trust_set_by_user
            iconRes = R.drawable.ic_boot_locked_24
            colorAttrRes = rikka.material.R.attr.colorInactive
        } else {
            titleRes = R.string.bootloader_locked
            summaryRes = 0
            iconRes = R.drawable.ic_boot_locked_24
            colorAttrRes = rikka.material.R.attr.colorSafe
        }

        val color = context.theme.resolveColor(colorAttrRes)

        binding.apply {
            title.setText(titleRes)
            icon.setImageDrawable(context.getDrawable(iconRes))
            root.backgroundTintList = ColorStateList.valueOf(color)
            if (summaryRes == 0) {
                summary.isVisible = false
            } else {
                summary.isVisible = true
                summary.setText(summaryRes)
            }
        }
    }
}
