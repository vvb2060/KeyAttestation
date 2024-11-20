-allowaccessmodification
-repackageclasses

-keepclassmembers class * implements android.os.Parcelable {
    public static final ** CREATOR;
}

-assumenosideeffects class kotlin.jvm.internal.Intrinsics {
	public static void check*(...);
	public static void throw*(...);
}

-assumenosideeffects class java.util.Objects{
    ** requireNonNull(...);
}

-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}

-keep class com.google.android.material.theme.MaterialComponentsViewInflater {
    <init>();
}
