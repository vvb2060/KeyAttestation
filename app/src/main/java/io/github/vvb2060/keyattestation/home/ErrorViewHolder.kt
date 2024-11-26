package io.github.vvb2060.keyattestation.home

import android.view.View
import io.github.vvb2060.keyattestation.R
import io.github.vvb2060.keyattestation.databinding.HomeErrorBinding
import io.github.vvb2060.keyattestation.lang.AttestationException
import rikka.html.text.HtmlCompat
import rikka.html.text.toHtml

class ErrorViewHolder(itemView: View, binding: HomeErrorBinding) : HomeViewHolder<AttestationException, HomeErrorBinding>(itemView, binding) {

    companion object {

        val CREATOR = Creator<AttestationException> { inflater, parent ->
            val binding = HomeErrorBinding.inflate(inflater, parent, false)
            ErrorViewHolder(binding.root, binding)
        }
    }

    override fun onBind() {
        val context = itemView.context
        binding.apply {
            val sb = StringBuilder()
            sb.append(context.getString(data.descriptionResId)).append("<p>")

            sb.append(context.getString(R.string.error_message_subtitle)).append("<br>")
            sb.append("<font face=\"monospace\">")
            var tr = data.cause
            while (tr != null) {
                sb.append(tr).append("<br>")
                tr = tr.cause
            }
            sb.append("</font>")
            text1.text = sb.toHtml(HtmlCompat.FROM_HTML_OPTION_TRIM_WHITESPACE)
        }
    }
}
