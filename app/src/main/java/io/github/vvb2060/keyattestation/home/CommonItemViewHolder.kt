package io.github.vvb2060.keyattestation.home

import android.view.View
import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.attestation.Attestation.*
import io.github.vvb2060.keyattestation.databinding.HomeCommonItemBinding
import io.github.vvb2060.keyattestation.util.ViewBindingViewHolder
import rikka.recyclerview.BaseViewHolder.Creator

open class CommonItemViewHolder<T>(itemView: View, binding: HomeCommonItemBinding) : ViewBindingViewHolder<T, HomeCommonItemBinding>(itemView, binding) {

    companion object {

        val COMMON_CREATOR = Creator<Pair<Int, String>> { inflater, parent ->
            val binding = HomeCommonItemBinding.inflate(inflater, parent, false)
            object : CommonItemViewHolder<Pair<Int, String>>(binding.root, binding) {

                init {
                    itemView.setOnClickListener {

                    }
                }

                override fun onBind() {
                    val data = data

                    binding.title.setText(data.first)
                    binding.summary.text = data.second
                }
            }
        }

        val SECURITY_LEVEL_CREATOR = Creator<Pair<Int, Int>> { inflater, parent ->
            val binding = HomeCommonItemBinding.inflate(inflater, parent, false)
            object : CommonItemViewHolder<Pair<Int, Int>>(binding.root, binding) {

                init {
                    itemView.setOnClickListener {

                    }
                }

                override fun onBind() {
                    val data = data

                    binding.title.setText(data.first)
                    binding.summary.setText(when (data.second) {
                        KM_SECURITY_LEVEL_SOFTWARE -> R.string.security_level_software
                        KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> R.string.security_level_trusted_environment
                        KM_SECURITY_LEVEL_STRONG_BOX -> R.string.security_level_strongbox
                        else -> 0
                    })
                }
            }
        }
    }

    init {
        setIsRecyclable(false)
    }
}