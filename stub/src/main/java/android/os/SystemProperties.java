package android.os;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public class SystemProperties {
    @NonNull
    public static String get(@NonNull String key) {
        throw new RuntimeException("Stub!");
    }

    @NonNull
    public static String get(@NonNull String key, @Nullable String def) {
        throw new RuntimeException("Stub!");
    }

    public static int getInt(@NonNull String key, int def) {
        throw new RuntimeException("Stub!");
    }

    public static long getLong(@NonNull String key, long def) {
        throw new RuntimeException("Stub!");
    }

    public static boolean getBoolean(@NonNull String key, boolean def) {
        throw new RuntimeException("Stub!");
    }

    public static void set(@NonNull String key, @Nullable String val) {
        throw new RuntimeException("Stub!");
    }

    public static void addChangeCallback(@NonNull Runnable callback) {
        throw new RuntimeException("Stub!");
    }

    public static void removeChangeCallback(@NonNull Runnable callback) {
        throw new RuntimeException("Stub!");
    }

    public static void reportSyspropChanged() {
        throw new RuntimeException("Stub!");
    }

    public static @NonNull String digestOf(@NonNull String... keys) {
        throw new RuntimeException("Stub!");
    }

    private SystemProperties() {
        throw new RuntimeException("Stub!");
    }

    @Nullable public static Handle find(@NonNull String name) {
        throw new RuntimeException("Stub!");
    }

    public static final class Handle {
        @NonNull public String get() {
            throw new RuntimeException("Stub!");
        }

        public int getInt(int def) {
            throw new RuntimeException("Stub!");
        }

        public long getLong(long def) {
            throw new RuntimeException("Stub!");
        }

        public boolean getBoolean(boolean def) {
            throw new RuntimeException("Stub!");
        }

        private Handle(long nativeHandle) {
            throw new RuntimeException("Stub!");
        }
    }
}
