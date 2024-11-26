package io.github.vvb2060.keyattestation.home

import android.content.res.ColorStateList
import android.view.View
import androidx.core.view.isVisible
import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.repository.AttestationData
import io.github.vvb2060.keyattestation.attestation.RootOfTrust
import io.github.vvb2060.keyattestation.databinding.HomeHeaderBinding
import rikka.core.res.resolveColor

class BootStateViewHolder(itemView: View, binding: HomeHeaderBinding) :
        HomeViewHolder<AttestationData, HomeHeaderBinding>(itemView, binding) {

    companion object {

        val CREATOR = Creator<AttestationData> { inflater, parent ->
            val binding = HomeHeaderBinding.inflate(inflater, parent, false)
            BootStateViewHolder(binding.root, binding)
        }
    }

    override fun onBind() {
        val context = itemView.context

        val rootOfTrust = data.rootOfTrust
        val locked = rootOfTrust?.isDeviceLocked
        val bootUnverified = rootOfTrust?.verifiedBootState != RootOfTrust.KM_VERIFIED_BOOT_VERIFIED

        val titleRes: Int
        val summaryRes: Int
        val iconRes: Int
        val colorAttrRes: Int

        if (locked == null) {
            titleRes = R.string.bootloader_unknown
            iconRes = R.drawable.ic_boot_unknown_24
            colorAttrRes = rikka.material.R.attr.colorInactive
        } else if (!locked) {
            titleRes = R.string.bootloader_unlocked
            iconRes = R.drawable.ic_boot_unlocked_24
            colorAttrRes = rikka.material.R.attr.colorWarning
        } else if (bootUnverified) {
            titleRes = R.string.bootloader_user
            iconRes = R.drawable.ic_boot_locked_24
            colorAttrRes = rikka.material.R.attr.colorInactive
        } else {
            titleRes = R.string.bootloader_locked
            iconRes = R.drawable.ic_boot_locked_24
            colorAttrRes = rikka.material.R.attr.colorSafe
        }

        if (data.isSoftwareLevel) {
            summaryRes = R.string.bootloader_summary_sw_level
        } else {
            summaryRes = 0
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
