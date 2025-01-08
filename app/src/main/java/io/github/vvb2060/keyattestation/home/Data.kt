package io.github.vvb2060.keyattestation.home

import android.content.Context
import io.github.vvb2060.keyattestation.R
import rikka.html.text.HtmlCompat
import rikka.html.text.toHtml

abstract class Data {
    abstract val title: Int
    abstract val description: Int
    open fun getMessage(context: Context): CharSequence =
        context.getString(description).toHtml(HtmlCompat.FROM_HTML_OPTION_TRIM_WHITESPACE)
}

class CommonData(
    override val title: Int,
    override val description: Int,
    val data: String? = null
) : Data()

class StringData(
    override val title: Int,
    val data: String,
) : Data() {
    override val description = 0
    override fun getMessage(context: Context) = data
}

class HeaderData(
    override val title: Int,
    override val description: Int,
    val icon: Int,
    val color: Int
) : Data()

class AuthorizationItemData(
    override val title: Int,
    override val description: Int,
    val data: String,
    val tee: Boolean
) : Data() {
    constructor(title: Int, description: Int, data: String?, fallback: String?) :
            this(title, description, data ?: fallback!!, data != null)

    override fun getMessage(context: Context): CharSequence {
        val id = if (tee) R.string.tee_enforced_description else R.string.sw_enforced_description
        return "${context.getString(description)}<p>* ${context.getString(id)}"
            .toHtml(HtmlCompat.FROM_HTML_OPTION_TRIM_WHITESPACE)
    }
}

class SecurityLevelData(
    override val title: Int,
    override val description: Int,
    val securityLevelDescription: Int,
    val version: String,
    val securityLevel: Int
) : Data() {
    override fun getMessage(context: Context): CharSequence {
        val flags = HtmlCompat.FROM_HTML_SEPARATOR_LINE_BREAK_LIST_ITEM or
                HtmlCompat.FROM_HTML_OPTION_TRIM_WHITESPACE
        return ("${context.getString(description)}<p>" +
                context.getString(securityLevelDescription)).toHtml(flags)
    }
}
