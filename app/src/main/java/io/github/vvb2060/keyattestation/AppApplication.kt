package io.github.vvb2060.keyattestation

import android.app.Application
import android.content.Context
import android.os.Handler
import android.os.Looper
import org.bouncycastle.jce.provider.BouncyCastleProvider
import rikka.html.text.HtmlCompat
import rikka.material.app.DayNightDelegate
import java.security.Security
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class AppApplication : Application() {
    companion object {
        const val TAG = "KeyAttestation"
        lateinit var app: AppApplication
        lateinit var mainHandler: Handler
        val executor: ExecutorService = Executors.newCachedThreadPool()
    }

    init {
        app = this
        mainHandler = Handler(Looper.getMainLooper())
        DayNightDelegate.setApplicationContext(this)
        DayNightDelegate.setDefaultNightMode(DayNightDelegate.MODE_NIGHT_FOLLOW_SYSTEM)
        HtmlCompat.setContext(this)
        install(this)
    }

    private fun install(context: Context) = executor.execute {
        if (BuildConfig.DEBUG) {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
            return@execute
        }
        runCatching {
            val gms = context.createPackageContext("com.google.android.gms",
                    Context.CONTEXT_INCLUDE_CODE or Context.CONTEXT_IGNORE_SECURITY)
            gms.classLoader
                    .loadClass("com.google.android.gms.common.security.ProviderInstallerImpl")
                    .getMethod("insertProvider", Context::class.java)
                    .invoke(null, gms)
        }
    }
}
