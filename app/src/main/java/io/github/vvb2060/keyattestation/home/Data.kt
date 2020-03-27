package io.github.vvb2060.keyattestation.home

import androidx.annotation.StringRes

abstract class Data {

    abstract val title: Int
        @StringRes get

    abstract val description: Int
        @StringRes get
}

data class CommonData(override val title: Int, override val description: Int, val data: String?) : Data()

data class AuthorizationItemData(override val title: Int, override val description: Int, val data: String?, val tee: Boolean) : Data()

data class SecurityLevelData(override val title: Int, override val description: Int, val securityLevelDescription: Int, val version: Int, val securityLevel: Int) : Data()

data class SubtitleData(override val title: Int, override val description: Int) : Data()