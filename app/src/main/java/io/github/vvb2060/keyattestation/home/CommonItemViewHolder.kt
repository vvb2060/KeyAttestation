package io.github.vvb2060.keyattestation.home

import android.util.Pair
import android.view.View
import androidx.core.view.isVisible
import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.attestation.Attestation.KM_SECURITY_LEVEL_STRONG_BOX
import io.github.vvb2060.keyattestation.attestation.Attestation.KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT
import io.github.vvb2060.keyattestation.attestation.AuthorizationList
import io.github.vvb2060.keyattestation.attestation.CertificateInfo
import io.github.vvb2060.keyattestation.attestation.RootPublicKey
import io.github.vvb2060.keyattestation.databinding.HomeCommonItemBinding
import rikka.core.res.resolveColorStateList

open class CommonItemViewHolder<T>(itemView: View, binding: HomeCommonItemBinding) :
    HomeViewHolder<T, HomeCommonItemBinding>(itemView, binding) {

    companion object {
        val SIMPLE_CREATOR = Creator<Pair<String, String>> { inflater, parent ->
            val binding = HomeCommonItemBinding.inflate(inflater, parent, false)
            object : CommonItemViewHolder<Pair<String, String>>(binding.root, binding) {

                init {
                    this.binding.apply {
                        text1.isVisible = false
                        icon.isVisible = false
                    }
                }

                override fun onBind() {
                    binding.title.text = data.first
                    binding.summary.text = data.second
                }
            }
        }

        val HOSTNAME_CREATOR = Creator<StringData> { inflater, parent ->
            val binding = HomeCommonItemBinding.inflate(inflater, parent, false)
            object : CommonItemViewHolder<StringData>(binding.root, binding) {

                init {
                    this.binding.apply {
                        icon.isVisible = false
                        root.setOnClickListener {
                            listener.onRkpHostnameClick(data.data)
                        }
                    }
                }

                override fun onBind() {
                    binding.title.setText(data.title)
                    if (data.data.isEmpty()) {
                        binding.summary.setText(R.string.rkp_hostname_empty)
                    } else {
                        binding.summary.text = data.data
                    }
                }
            }
        }

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
                    if (data.data.isNullOrEmpty()) {
                        binding.summary.setText(R.string.empty)
                    } else {
                        binding.summary.text = data.data
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
                            listener.onCommonDataClick(data)
                        }
                        icon.isVisible = false
                    }
                }

                override fun onBind() {
                    binding.apply {
                        title.setText(data.title)
                        text1.setText(if (data.tee) R.string.tee_enforced else R.string.sw_enforced)
                        if (data.data.isEmpty()) {
                            summary.setText(R.string.empty)
                        } else {
                            summary.text = data.data
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
                            listener.onCommonDataClick(data)
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
                        icon.setOnClickListener {
                            data.attestation?.let { listener.onAttestationInfoClick(it) }
                        }
                        root.setOnClickListener {
                            val stringData = StringData(R.string.cert_info, data.cert.toString())
                            listener.onCommonDataClick(stringData)
                        }
                    }
                }

                override fun onBind() {
                    val iconRes: Int?
                    val colorAttr: Int?
                    binding.icon.apply {
                        if (data.issuer == RootPublicKey.Status.AOSP) {
                            isVisible = true
                            isClickable = false
                            iconRes = R.drawable.ic_untrustworthy_24
                            colorAttr = rikka.material.R.attr.colorWarning
                        } else if (data.issuer == RootPublicKey.Status.GOOGLE) {
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

                    data.provisioningInfo?.apply {
                        certsIssued?.let {
                            sb.append("\n")
                                .append(res.getString(R.string.provisioning_info_certs_issued))
                                .append(it)
                        }
                        manufacturer?.let {
                            sb.append("\n")
                                .append(res.getString(R.string.provisioning_info_manufacturer))
                                .append(it)
                        }
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
