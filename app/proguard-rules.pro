-allowaccessmodification
-repackageclasses
-keepclassmembers class * implements android.os.Parcelable {
    public static final ** CREATOR;
}

-assumenosideeffects class kotlin.jvm.internal.Intrinsics {
	public static void check*(...);
	public static void throw*(...);
}

-keepattributes SourceFile,LineNumberTable
-keep public class * extends java.lang.Exception
