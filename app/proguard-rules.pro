# CameraX
-keep class androidx.camera.** { *; }
-dontwarn androidx.camera.**

# ML Kit Barcode
-keep class com.google.mlkit.** { *; }
-dontwarn com.google.mlkit.**
-keep class com.google.android.gms.internal.mlkit_** { *; }
-dontwarn com.google.android.gms.internal.mlkit_**

# Retrofit/Moshi (reflexe)
-keep class com.squareup.moshi.** { *; }
-keep class kotlin.Metadata { *; }

# Keep Hilt, Retrofit/Moshi models
-keep class dagger.hilt.** { *; }
-keep class com.squareup.moshi.** { *; }
-keep class com.cybersentinel.app.** { *; }
-dontwarn okio.**
-dontwarn javax.annotation.**