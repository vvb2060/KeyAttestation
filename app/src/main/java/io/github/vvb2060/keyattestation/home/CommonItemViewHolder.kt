package io.github.vvb2060.keyattestation.home

import android.view.View
import androidx.core.view.isVisible
import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.app.AlertDialogFragment
import io.github.vvb2060.keyattestation.app.AppActivity
import io.github.vvb2060.keyattestation.attestation.Attestation.KM_SECURITY_LEVEL_STRONG_BOX
import io.github.vvb2060.keyattestation.attestation.Attestation.KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT
import io.github.vvb2060.keyattestation.databinding.HomeCommonItemBinding
import io.github.vvb2060.keyattestation.ktx.toHtml
import io.github.vvb2060.keyattestation.util.ViewBindingViewHolder
import rikka.core.res.resolveColorStateList
import rikka.html.text.HtmlCompat
import rikka.recyclerview.BaseViewHolder.Creator

open class CommonItemViewHolder<T>(itemView: View, binding: HomeCommonItemBinding) : ViewBindingViewHolder<T, HomeCommonItemBinding>(itemView, binding) {

    companion object {

        val COMMON_CREATOR = Creator<CommonData> { inflater, parent ->
            val binding = HomeCommonItemBinding.inflate(inflater, parent, false)
            object : CommonItemViewHolder<CommonData>(binding.root, binding) {

                init {
                    this.binding.icon.isVisible = false
                    this.itemView.setOnClickListener {
                        AlertDialogFragment.Builder(it.context)
                                .title(data.title)
                                .message(it.context.getString(data.description).toHtml(HtmlCompat.FROM_HTML_OPTION_TRIM_WHITESPACE))
                                .positiveButton(android.R.string.ok)
                                .build()
                                .show((it.context as AppActivity).supportFragmentManager)
                    }
                }

                override fun onBind() {
                    binding.title.setText(data.title)
                    binding.summary.text = data.data
                }
            }
        }

        val SECURITY_LEVEL_CREATOR = Creator<SecurityLevelData> { inflater, parent ->
            val binding = HomeCommonItemBinding.inflate(inflater, parent, false)
            object : CommonItemViewHolder<SecurityLevelData>(binding.root, binding) {

                init {
                    this.itemView.setOnClickListener {
                        AlertDialogFragment.Builder(itemView.context)
                                .title(data.title)
                                .message("${context.getString(data.description)}<p>${context.getString(data.securityLevelDescription)}".toHtml(HtmlCompat.FROM_HTML_SEPARATOR_LINE_BREAK_LIST_ITEM or HtmlCompat.FROM_HTML_OPTION_TRIM_WHITESPACE))
                                .positiveButton(android.R.string.ok)
                                .build()
                                .show((itemView.context as AppActivity).supportFragmentManager)
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