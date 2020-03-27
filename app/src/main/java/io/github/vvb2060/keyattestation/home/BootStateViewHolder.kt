package io.github.vvb2060.keyattestation.home

import android.content.res.ColorStateList
import android.view.View
import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.attestation.AttestationResult
import io.github.vvb2060.keyattestation.databinding.HomeBootStateBinding
import rikka.core.res.resolveColor
import rikka.recyclerview.BaseViewHolder.Creator

class BootStateViewHolder(itemView: View, binding: HomeBootStateBinding) : HomeViewHolder<AttestationResult, HomeBootStateBinding>(itemView, binding) {

    companion object {

        val CREATOR = Creator<AttestationResult> { inflater, parent ->
            val binding = HomeBootStateBinding.inflate(inflater, parent, false)
            BootStateViewHolder(binding.root, binding)
        }
    }

    override fun onBind() {
        val context = itemView.context

        val attestation = data.attestation
        val locked = attestation.teeEnforced?.rootOfTrust?.isDeviceLocked

        val titleRes: Int
        val iconRes: Int
        val colorAttrRes: Int

        if (locked == null) {
            titleRes = R.string.bootloader_unknown
            iconRes = R.drawable.ic_boot_unknown_24
            colorAttrRes = R.attr.colorInactive
        } else if (!locked) {
            titleRes = R.string.bootloader_unlocked
            iconRes = R.drawable.ic_boot_unlocked_24
            colorAttrRes = R.attr.colorWarning
        } else {
            titleRes = R.string.bootloader_locked
            iconRes = R.drawable.ic_boot_locked_24
            colorAttrRes = R.attr.colorSafe
        }

        val color = context.theme.resolveColor(colorAttrRes)

        binding.title.setText(titleRes)
        binding.title.setCompoundDrawablesRelativeWithIntrinsicBounds(context.getDrawable(iconRes), null, null, null)
        binding.root.backgroundTintList = ColorStateList.valueOf(color)
    }
}