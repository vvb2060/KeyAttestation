package io.github.vvb2060.keyattestation

import android.util.Log
import de.robv.android.xposed.IXposedHookLoadPackage
import de.robv.android.xposed.XC_MethodHook
import de.robv.android.xposed.XposedBridge
import de.robv.android.xposed.XposedHelpers
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam
import java.util.*

class Xposed : IXposedHookLoadPackage {

    private fun isSafetyNet(param: LoadPackageParam) =
            param.packageName == "com.google.android.gms" &&
                    param.processName == "com.google.android.gms.unstable"

    private fun isDebugVersion(param: LoadPackageParam) =
            param.packageName == "io.github.vvb2060.keyattestation.debug"

    override fun handleLoadPackage(packageParam: LoadPackageParam) {
        if (!isDebugVersion(packageParam) && !isSafetyNet(packageParam)) return

        val hook: XC_MethodHook = object : XC_MethodHook() {
            override fun beforeHookedMethod(param: MethodHookParam) {
                Log.d(TAG, "New key attestation request: ${Arrays.toString(param.args)}")
                param.result = -10003
            }
        }

        /**
        https://android.googlesource.com/platform/system/security/+/refs/tags/android-10.0.0_r36/keystore/binder/android/security/keystore/IKeystoreService.aidl#67
        Bp: app's process space
        Bn: keystore daemon
         */
        XposedHelpers.findClassIfExists(
                "android.security.KeyStore", packageParam.classLoader)
                ?.declaredMethods?.find { it.name == "attestKey" }
                ?.let { XposedBridge.hookMethod(it, hook) }
                ?.apply { Log.d(TAG, "KeyStore method hooked: $hookedMethod") }
    }

    companion object {
        const val TAG = "Xposed"
    }
}
