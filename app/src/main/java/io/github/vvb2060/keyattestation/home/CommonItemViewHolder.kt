package io.github.vvb2060.keyattestation.home

import android.view.View
import androidx.core.view.isVisible
import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.attestation.Attestation.KM_SECURITY_LEVEL_STRONG_BOX
import io.github.vvb2060.keyattestation.attestation.Attestation.KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT
import io.github.vvb2060.keyattestation.databinding.HomeCommonItemBinding
import rikka.core.res.resolveColorStateList
import rikka.recyclerview.BaseViewHolder.Creator

open class CommonItemViewHolder<T>(itemView: View, binding: HomeCommonItemBinding) : HomeViewHolder<T, HomeCommonItemBinding>(itemView, binding) {

    companion object {

        val COMMON_CREATOR = Creator<CommonData> { inflater, parent ->
            val binding = HomeCommonItemBinding.inflate(inflater, parent, false)
            object : CommonItemViewHolder<CommonData>(binding.root, binding) {

                init {
                    this.binding.icon.isVisible = false
                    this.itemView.setOnClickListener {
                        listener.onCommonDataClick(data)
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

        val SECURITY_LEVEL_CREATOR = Creator<SecurityLevelData> { inflater, parent ->
            val binding = HomeCommonItemBinding.inflate(inflater, parent, false)
            object : CommonItemViewHolder<SecurityLevelData>(binding.root, binding) {

                init {
                    this.itemView.setOnClickListener {
                        listener.onSecurityLevelDataClick(data)
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
                            colorAttr = R.attr.colorSafe
                        }
                        KM_SECURITY_LEVEL_STRONG_BOX -> {
                            securityLevel = R.string.security_level_strongbox
                            iconRes = R.drawable.ic_trustworthy_24
                            colorAttr = R.attr.colorSafe
                        }
                        else -> {
                            securityLevel = R.string.security_level_software
                            iconRes = R.drawable.ic_untrustworthy_24
                            colorAttr = R.attr.colorWarning
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
    }

    init {
        setIsRecyclable(false)
    }
}