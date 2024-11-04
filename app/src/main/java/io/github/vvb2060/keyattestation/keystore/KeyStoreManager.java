package io.github.vvb2060.keyattestation.keystore;

import android.annotation.SuppressLint;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.PackageManager;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;

import androidx.annotation.NonNull;

import io.github.vvb2060.keyattestation.AppApplication;
import io.github.vvb2060.keyattestation.BuildConfig;
import rikka.shizuku.Shizuku;

public class KeyStoreManager {
    private static IAndroidKeyStore remoteKeyStore;
    private static boolean installed;

    public static IAndroidKeyStore getRemoteKeyStore() {
        return remoteKeyStore;
    }

    public static boolean isShizukuInstalled() {
        return installed;
    }

    private static void bindUserService() {
        if (remoteKeyStore != null) {
            return;
        }
        var name = new ComponentName(BuildConfig.APPLICATION_ID, AndroidKeyStore.class.getName());
        var args = new Shizuku.UserServiceArgs(name)
                .daemon(false)
                .debuggable(BuildConfig.DEBUG)
                .version(BuildConfig.VERSION_CODE)
                .processNameSuffix("keystore");
        var connection = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder service) {
                remoteKeyStore = IAndroidKeyStore.Stub.asInterface(service);
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                remoteKeyStore = null;
            }
        };
        Shizuku.bindUserService(args, connection);
    }

    public static void requestPermission() {
        if (Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) {
            bindUserService();
        } else if (Shizuku.shouldShowRequestPermissionRationale()) {
            Log.w(AppApplication.TAG, "shizuku permission denied");
        } else {
            Shizuku.addRequestPermissionResultListener(new Shizuku.OnRequestPermissionResultListener() {
                @Override
                public void onRequestPermissionResult(int requestCode, int grantResult) {
                    Shizuku.removeRequestPermissionResultListener(this);
                    if (grantResult == PackageManager.PERMISSION_GRANTED) {
                        bindUserService();
                    } else {
                        Log.w(AppApplication.TAG, "shizuku permission denied");
                    }
                }
            });
            Shizuku.requestPermission(0);
        }
    }

    public static void requestBinder(Context context) {
        var receiver = new Binder() {
            @SuppressLint("RestrictedApi")
            @Override
            protected boolean onTransact(int code, @NonNull Parcel data, Parcel reply, int flags) throws RemoteException {
                if (code == 1) {
                    installed = true;
                    var binder = data.readStrongBinder();
                    if (binder != null) {
                        Shizuku.onBinderReceived(binder, BuildConfig.APPLICATION_ID);
                        requestPermission();
                    } else {
                        Log.w(AppApplication.TAG, "shizuku is not running");
                    }

                    return true;
                }
                return super.onTransact(code, data, reply, flags);
            }
        };
        var data = new Bundle();
        data.putBinder("binder", receiver);
        var intent = new Intent("rikka.shizuku.intent.action.REQUEST_BINDER")
                .setPackage("moe.shizuku.privileged.api")
                .addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES)
                .putExtra("data", data);
        context.sendBroadcast(intent);
    }
}
