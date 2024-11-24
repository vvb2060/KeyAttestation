package io.github.vvb2060.keyattestation.keystore;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.SystemProperties;
import android.telephony.TelephonyManager_rename;
import android.util.Log;

import java.util.concurrent.Executor;

import io.github.vvb2060.keyattestation.AppApplication;

public class ContextHook extends ContextWrapper {
    private final TelephonyManager_rename telephonyService = new TelephonyManager_rename(this) {
        @Override
        public String getImei(int slotIndex) {
            String imei = null;
            try {
                imei = super.getImei(slotIndex);
            } catch (SecurityException e) {
                Log.w(AppApplication.TAG, "getImei", e);
            }
            if (imei == null) {
                var slot = slotIndex == 0 ? "" : "2";
                var prop = SystemProperties.get("ro.ril.oem.imei" + slot);
                return prop.isEmpty() ? null : prop;
            }
            return imei;
        }

        @Override
        public String getMeid(int slotIndex) {
            String meid = null;
            try {
                meid = super.getMeid(slotIndex);
            } catch (SecurityException e) {
                Log.w(AppApplication.TAG, "getMeid", e);
            }
            if (meid == null) {
                var prop = SystemProperties.get("ro.ril.oem.meid");
                return prop.isEmpty() ? null : prop;
            }
            return meid;
        }
    };

    private ContextHook(Context base) {
        super(base);
    }

    @Override
    public Object getSystemService(String name) {
        if (Context.TELEPHONY_SERVICE.equals(name)) {
            return telephonyService;
        }
        return super.getSystemService(name);
    }

    @Override
    public boolean bindService(Intent service, int flags, Executor executor, ServiceConnection conn) {
        return false;
    }

    @Override
    public boolean bindService(Intent service, ServiceConnection conn, int flags) {
        return false;
    }

    public static void hook(ContextWrapper context) throws Exception {
        var wrapper = new ContextHook(context.getBaseContext());
        //noinspection JavaReflectionMemberAccess DiscouragedPrivateApi
        var base = ContextWrapper.class.getDeclaredField("mBase");
        base.setAccessible(true);
        base.set(context, wrapper);
    }
}
