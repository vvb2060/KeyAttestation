package io.github.vvb2060.keyattestation

import kotlin.apply
import kotlin.collections.find
import kotlin.let

class Xposed : de.robv.android.xposed.IXposedHookLoadPackage {

    private fun isSafetyNet(param: de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam) =
            param.packageName == "com.google.android.gms" &&
                    param.processName == "com.google.android.gms.unstable"

    private fun isDebugVersion(param: de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam) =
            param.packageName == "io.github.vvb2060.keyattestation.debug"

    override fun handleLoadPackage(packageParam: de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam) {
        if (!isDebugVersion(packageParam) && !isSafetyNet(packageParam)) return

        val hook: de.robv.android.xposed.XC_MethodHook = object : de.robv.android.xposed.XC_MethodHook() {
            override fun beforeHookedMethod(param: de.robv.android.xposed.XC_MethodHook.MethodHookParam) {
                android.util.Log.d(TAG, "New key attestation request: ${java.util.Arrays.toString(param.args)}")
                param.result = -10003
            }
        }

        /**
        https://android.googlesource.com/platform/system/security/+/refs/tags/android-10.0.0_r36/keystore/binder/android/security/keystore/IKeystoreService.aidl#67
        Bp: app's process space
        Bn: keystore daemon
         */
        de.robv.android.xposed.XposedHelpers.findClassIfExists(
                "android.security.KeyStore", packageParam.classLoader)
                ?.declaredMethods?.find { it.name == "attestKey" }
                ?.let { de.robv.android.xposed.XposedBridge.hookMethod(it, hook) }
                ?.apply { android.util.Log.d(TAG, "KeyStore method hooked: $hookedMethod") }
    }

    companion object {
        const val TAG = "Xposed"
    }
}