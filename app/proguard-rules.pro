-allowaccessmodification
-repackageclasses

-assumenosideeffects class kotlin.jvm.internal.Intrinsics {
	public static void checkExpressionValueIsNotNull(...);
	public static void checkNotNullExpressionValue(...);
	public static void checkReturnedValueIsNotNull(...);
	public static void checkFieldIsNotNull(...);
	public static void checkParameterIsNotNull(...);
}

-keepattributes SourceFile,LineNumberTable
-keep public class * extends java.lang.Exception

-keep,allowoptimization class io.github.vvb2060.keyattestation.Xposed
