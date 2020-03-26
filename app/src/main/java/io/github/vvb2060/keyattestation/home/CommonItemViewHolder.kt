package io.github.vvb2060.keyattestation.home

import android.view.View
import androidx.core.view.isVisible
import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.attestation.Attestation.KM_SECURITY_LEVEL_STRONG_BOX
import io.github.vvb2060.keyattestation.attestation.Attestation.KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT
import io.github.vvb2060.keyattestation.databinding.HomeCommonItemBinding
import io.github.vvb2060.keyattestation.util.ViewBindingViewHolder
import rikka.core.res.resolveColorStateList
import rikka.recyclerview.BaseViewHolder.Creator

open class CommonItemViewHolder<T>(itemView: View, binding: HomeCommonItemBinding) : ViewBindingViewHolder<T, HomeCommonItemBinding>(itemView, binding) {

    companion object {

        val COMMON_CREATOR = Creator<Pair<Int, String>> { inflater, parent ->
            val binding = HomeCommonItemBinding.inflate(inflater, parent, false)
            object : CommonItemViewHolder<Pair<Int, String>>(binding.root, binding) {

                init {
                    this.binding.icon.isVisible = false
                    this.itemView.setOnClickListener {

                    }
                }

                override fun onBind() {
                    val data = data

                    binding.title.setText(data.first)
                    binding.summary.text = data.second
                }
            }
        }

        val SECURITY_LEVEL_CREATOR = Creator<Pair<Int, Array<Int>>> { inflater, parent ->
            val binding = HomeCommonItemBinding.inflate(inflater, parent, false)
            object : CommonItemViewHolder<Pair<Int, Array<Int>>>(binding.root, binding) {

                init {
                    this.itemView.setOnClickListener {

                    }
                }

                override fun onBind() {
                    val context = itemView.context
                    val data = data
                    val securityLevel: Int
                    val iconRes: Int
                    val colorAttr: Int
                    when (data.second[1]) {
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
                        title.setText(data.first)
                        summary.text = context.getString(R.string.attestation_summary_format, data.second[0], context.getString(securityLevel))
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