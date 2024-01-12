package io.github.vvb2060.keyattestation.home

import android.view.View
import androidx.core.view.isVisible
import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.attestation.Attestation.KM_SECURITY_LEVEL_STRONG_BOX
import io.github.vvb2060.keyattestation.attestation.Attestation.KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT
import io.github.vvb2060.keyattestation.attestation.AuthorizationList
import io.github.vvb2060.keyattestation.attestation.CertificateInfo
import io.github.vvb2060.keyattestation.databinding.HomeCommonItemBinding
import rikka.core.res.resolveColorStateList
import rikka.recyclerview.BaseViewHolder.Creator

open class CommonItemViewHolder<T>(itemView: View, binding: HomeCommonItemBinding) : HomeViewHolder<T, HomeCommonItemBinding>(itemView, binding) {

    companion object {

        val COMMON_CREATOR = Creator<CommonData> { inflater, parent ->
            val binding = HomeCommonItemBinding.inflate(inflater, parent, false)
            object : CommonItemViewHolder<CommonData>(binding.root, binding) {

                init {
                    this.binding.apply {
                        icon.isVisible = false
                        root.setOnClickListener {
                            listener.onCommonDataClick(data)
                        }
                    }
                }

                override fun onBind() {
                    binding.title.setText(data.title)
                    if (!data.data.isNullOrBlank()) {
                        binding.summary.text = data.data
                    } else {
                        binding.summary.setText(R.string.empty)
                    }
                }
            }
        }

        val AUTHORIZATION_ITEM_CREATOR = Creator<AuthorizationItemData> { inflater, parent ->
            val binding = HomeCommonItemBinding.inflate(inflater, parent, false)
            object : CommonItemViewHolder<AuthorizationItemData>(binding.root, binding) {

                init {
                    this.binding.apply {
                        root.setOnClickListener {
                            listener.onAuthorizationItemDataClick(data)
                        }
                        icon.isVisible = false
                    }
                }

                override fun onBind() {
                    binding.apply {
                        title.setText(data.title)
                        if (!data.data.isNullOrBlank()) {
                            summary.text = data.data
                            text1.setText(if (data.tee) R.string.tee_enforced else R.string.sw_enforced)
                            text1.isVisible = true
                        } else {
                            summary.setText(R.string.empty)
                            text1.isVisible = false
                        }
                    }
                }
            }
        }

        val SECURITY_LEVEL_CREATOR = Creator<SecurityLevelData> { inflater, parent ->
            val binding = HomeCommonItemBinding.inflate(inflater, parent, false)
            object : CommonItemViewHolder<SecurityLevelData>(binding.root, binding) {

                init {
                    this.binding.apply {
                        text1.isVisible = false
                        icon.background = null
                        root.setOnClickListener {
                            listener.onSecurityLevelDataClick(data)
                        }
                    }
                }

                override fun onBind() {
                    val context = itemView.context
                    val data = data
                    val securityLevel: Int
                    val iconRes: Int
                    val colorAttr: Int
                    when (data.securityLevel) {
                        KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> {
                            securityLevel = R.string.security_level_trusted_environment
                            iconRes = R.drawable.ic_trustworthy_24
                            colorAttr = rikka.material.R.attr.colorSafe
                        }
                        KM_SECURITY_LEVEL_STRONG_BOX -> {
                            securityLevel = R.string.security_level_strongbox
                            iconRes = R.drawable.ic_trustworthy_24
                            colorAttr = rikka.material.R.attr.colorSafe
                        }
                        else -> {
                            securityLevel = R.string.security_level_software
                            iconRes = R.drawable.ic_untrustworthy_24
                            colorAttr = rikka.material.R.attr.colorWarning
                        }
                    }

                    binding.apply {
                        title.setText(data.title)
                        summary.text = context.getString(R.string.attestation_summary_format, data.version, context.getString(securityLevel))
                        icon.setImageDrawable(context.getDrawable(iconRes))
                        icon.imageTintList = context.theme.resolveColorStateList(colorAttr)
                    }
                }
            }
        }

        val CERT_INFO_CREATOR = Creator<CertificateInfo> { inflater, parent ->
            val binding = HomeCommonItemBinding.inflate(inflater, parent, false)
            object : CommonItemViewHolder<CertificateInfo>(binding.root, binding) {

                init {
                    this.binding.apply {
                        title.isVisible = false
                        text1.isVisible = false
                        icon.background = null
                    }
                }

                override fun onBind() {
                    val iconRes: Int?
                    val colorAttr: Int?
                    binding.icon.apply {
                        setOnClickListener {
                            data.attestation?.let { listener.onAttestationInfoClick(it) }
                        }
                        if (data.issuer == CertificateInfo.KEY_AOSP) {
                            isVisible = true
                            isClickable = false
                            iconRes = R.drawable.ic_untrustworthy_24
                            colorAttr = rikka.material.R.attr.colorWarning
                        } else if (data.issuer == CertificateInfo.KEY_GOOGLE
                                    || data.issuer == CertificateInfo.KEY_SAMSUNG) {
                            isVisible = true
                            isClickable = false
                            iconRes = R.drawable.ic_trustworthy_24
                            colorAttr = rikka.material.R.attr.colorSafe
                        } else if (data.attestation != null) {
                            isVisible = true
                            isClickable = true
                            iconRes = R.drawable.ic_info_outline_24
                            colorAttr = rikka.material.R.attr.colorAccent
                        } else {
                            isVisible = false
                            isClickable = false
                            iconRes = null
                            colorAttr = null
                        }
                        iconRes?.let { setImageDrawable(context.getDrawable(it)) }
                        colorAttr?.let { imageTintList = context.theme.resolveColorStateList(it) }
                    }

                    binding.root.setOnClickListener {
                        listener.onCertInfoClick(data)
                    }

                    val sb = StringBuilder()
                    val cert = data.cert
                    val res = context.resources
                    sb.append(res.getString(R.string.cert_subject))
                            .append(cert.subjectDN)
                            .append("\n")
                            .append(res.getString(R.string.cert_not_before))
                            .append(AuthorizationList.formatDate(cert.notBefore))
                            .append("\n")
                            .append(res.getString(R.string.cert_not_after))
                            .append(AuthorizationList.formatDate(cert.notAfter))

                    if (data.certsIssued != null) {
                        sb.append("\n")
                                .append(res.getString(R.string.provisioning_info_certs_issued))
                                .append(data.certsIssued)
                    }

                    val resId = when (data.status) {
                        CertificateInfo.CERT_SIGN -> R.string.cert_error_sign
                        CertificateInfo.CERT_REVOKED -> R.string.cert_error_revoked
                        CertificateInfo.CERT_EXPIRED -> R.string.cert_error_expired
                        else -> null
                    }
                    if (resId != null) {
                        sb.append("\n").append(res.getString(resId))
                                .append(data.securityException.message)
                    }
                    binding.summary.text = sb.toString()
                }
            }
        }
    }
}
