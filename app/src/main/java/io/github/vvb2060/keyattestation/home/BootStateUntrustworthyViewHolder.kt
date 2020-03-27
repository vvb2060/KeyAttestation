package io.github.vvb2060.keyattestation.home

import android.view.View
import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.attestation.Attestation
import io.github.vvb2060.keyattestation.attestation.AttestationResult
import io.github.vvb2060.keyattestation.databinding.HomeBootStateUntrustworthyBinding
import rikka.recyclerview.BaseViewHolder.Creator

class BootStateUntrustworthyViewHolder(itemView: View, binding: HomeBootStateUntrustworthyBinding) : HomeViewHolder<AttestationResult, HomeBootStateUntrustworthyBinding>(itemView, binding) {

    companion object {

        val CREATOR = Creator<AttestationResult> { inflater, parent ->
            val binding = HomeBootStateUntrustworthyBinding.inflate(inflater, parent, false)
            BootStateUntrustworthyViewHolder(binding.root, binding)
        }
    }

    override fun onBind() {
        val attestation = data.attestation
        val isSoftware = attestation.attestationSecurityLevel == Attestation.KM_SECURITY_LEVEL_SOFTWARE

        val reason = if (isSoftware) R.string.untrustworthy_software else R.string.untrustworthy_not_google_cert
        binding.summary.setText(reason)
    }
}