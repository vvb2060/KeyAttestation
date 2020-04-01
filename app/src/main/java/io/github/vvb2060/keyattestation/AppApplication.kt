package io.github.vvb2060.keyattestation

import android.annotation.SuppressLint
import android.app.Application
import android.content.Context
import android.os.Build
import android.provider.Settings
import com.google.common.io.BaseEncoding
import com.google.firebase.analytics.FirebaseAnalytics
import com.google.firebase.crashlytics.FirebaseCrashlytics
import rikka.html.text.HtmlCompat
import rikka.material.app.DayNightDelegate

class AppApplication : Application() {

    init {
        DayNightDelegate.setApplicationContext(this)
        DayNightDelegate.setDefaultNightMode(DayNightDelegate.MODE_NIGHT_FOLLOW_SYSTEM)
        HtmlCompat.setContext(this)
    }

    @SuppressLint("HardwareIds")
    private fun getUserId(context: Context): String? {
        val ssaid = try {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
        } catch (e: Throwable) {
            null
        } ?: return null

        return BaseEncoding.base64().encode((Build.BRAND + Build.MODEL + ssaid).toByteArray())
    }

    override fun onCreate() {
        super.onCreate()

        val userId = getUserId(this)
        if (userId != null) {
            FirebaseAnalytics.getInstance(this).apply { setUserId(userId) }
            FirebaseCrashlytics.getInstance().apply { setUserId(userId) }
        } else {
            FirebaseAnalytics.getInstance(this).setAnalyticsCollectionEnabled(false)
            FirebaseCrashlytics.getInstance().setCrashlyticsCollectionEnabled(false)
        }
    }
}