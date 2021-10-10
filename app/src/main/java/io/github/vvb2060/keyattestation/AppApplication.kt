package io.github.vvb2060.keyattestation

import android.annotation.SuppressLint
import android.app.Application
import android.content.Context
import android.provider.Settings
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
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID).trim()
        } catch (e: Throwable) {
            return null
        }
        try {
            if (ssaid == "9774d56d682e549c") return null
            if (Integer.parseInt(ssaid, 16) == 0) return null
        } catch (e: Throwable) {
        }
        return ssaid
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
