package io.github.vvb2060.keyattestation.util

import android.content.pm.PackageManager
import android.os.SystemProperties
import android.util.Log
import androidx.core.content.ContextCompat
import io.github.vvb2060.keyattestation.AppApplication

object SamsungUtils {
    private const val SAMSUNG_KEYSTORE_PERMISSION =
        "com.samsung.android.security.permission.SAMSUNG_KEYSTORE_PERMISSION"

    fun isSecAttestationSupported(): Boolean {
        if (!isSamsungKeystoreLibrarySupported()) {
            Log.w(AppApplication.TAG, "This device has no samsungkeystoreutils library, " +
                    "skipping SAK.")
            return false
        }

        if (!isSAKSupported()) {
            Log.w(AppApplication.TAG, "This device has no SAK support, " +
                    "skipping SAK.")
            return false
        }

        if (!isKeystorePermissionGranted()) {
            Log.e(AppApplication.TAG, "SAMSUNG_KEYSTORE_PERMISSION has not been granted to the app, " +
                    "skipping SAK.")
            return false
        }

        return true
    }

    private fun isSamsungKeystoreLibrarySupported(): Boolean {
        val pm: PackageManager = AppApplication.app.packageManager
        val systemSharedLibraries = pm.systemSharedLibraryNames

        if (systemSharedLibraries != null) {
            for (lib in systemSharedLibraries) {
                if (lib != null && lib.lowercase() == "samsungkeystoreutils") {
                    return true
                }
            }
        }

        return false
    }

    private fun isSAKSupported(): Boolean {
        return SystemProperties.get("ro.security.keystore.keytype", "").lowercase()
            .contains("sak")
    }

    private fun isKeystorePermissionGranted(): Boolean{
        return ContextCompat.checkSelfPermission(
            AppApplication.app, SAMSUNG_KEYSTORE_PERMISSION) ==
                PackageManager.PERMISSION_GRANTED
    }
}
