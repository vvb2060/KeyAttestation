package io.github.vvb2060.keyattestation.home

import android.view.View
import io.github.vvb2060.keyattestation.databinding.HomeErrorBinding
import io.github.vvb2060.keyattestation.lang.AttestationException
import rikka.recyclerview.BaseViewHolder.Creator

class ErrorViewHolder(itemView: View, binding: HomeErrorBinding) : HomeViewHolder<AttestationException, HomeErrorBinding>(itemView, binding) {

    companion object {

        val CREATOR = Creator<AttestationException> { inflater, parent ->
            val binding = HomeErrorBinding.inflate(inflater, parent, false)
            ErrorViewHolder(binding.root, binding)
        }
    }

    override fun onBind() {
        binding.apply {
            val sb = StringBuilder()
            var tr = data.cause
            while (tr?.cause != null && tr.cause != tr) {
                sb.append("${tr::class.java.name}: ${tr.message}").append("\n\n")
                tr = tr.cause
            }
            text1.text = sb.trim().toString()
        }
    }
}