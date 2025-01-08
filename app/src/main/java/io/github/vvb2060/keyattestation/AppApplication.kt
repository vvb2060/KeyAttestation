package io.github.vvb2060.keyattestation

import android.annotation.SuppressLint
import android.app.Application
import android.content.Context
import android.content.pm.PackageManager
import android.widget.Toast
import androidx.arch.core.executor.ArchTaskExecutor
import io.github.vvb2060.keyattestation.keystore.KeyStoreManager
import org.bouncycastle.jce.provider.BouncyCastleProvider
import rikka.html.text.HtmlCompat
import rikka.material.app.DayNightDelegate
import rikka.sui.Sui
import java.security.Security
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class AppApplication : Application() {
    companion object {
        const val TAG = "KeyAttestation"
        lateinit var app: AppApplication
        val executor: ExecutorService = Executors.newSingleThreadExecutor()

        @SuppressLint("RestrictedApi")
        fun toast(text: String?) {
            ArchTaskExecutor.getInstance().postToMainThread {
                Toast.makeText(app, text, Toast.LENGTH_LONG).show()
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        app = this
        DayNightDelegate.setApplicationContext(this)
        DayNightDelegate.setDefaultNightMode(DayNightDelegate.MODE_NIGHT_FOLLOW_SYSTEM)
        HtmlCompat.setContext(this)
        installProvider(this)

        if (Sui.init(BuildConfig.APPLICATION_ID)) {
            KeyStoreManager.requestPermission();
        } else {
            KeyStoreManager.requestBinder(this)
        }
    }

    private fun installProvider(context: Context) {
        if (BuildConfig.DEBUG) {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        } else runCatching {
            context.packageManager.getApplicationInfo("com.google.android.gms",
                    PackageManager.MATCH_SYSTEM_ONLY)
            val gms = context.createPackageContext("com.google.android.gms",
                    CONTEXT_INCLUDE_CODE or CONTEXT_IGNORE_SECURITY)
            gms.classLoader
                    .loadClass("com.google.android.gms.common.security.ProviderInstallerImpl")
                    .getMethod("insertProvider", Context::class.java)
                    .invoke(null, gms)
        }
    }
}
