package com.cybersentinel.app.domain.device

import android.content.Context
import android.os.Build
import dagger.hilt.android.qualifiers.ApplicationContext
import java.time.LocalDate
import javax.inject.Inject
import javax.inject.Singleton

data class DeviceProfile(
    val manufacturer: String,
    val model: String,
    val sdkInt: Int,
    val securityPatch: LocalDate?,
    val chromeVersion: String?,
    val webViewVersion: String?
)

@Singleton
class DeviceProfileProvider @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private fun pkgVersion(pkg: String) = runCatching {
        context.packageManager.getPackageInfo(pkg, 0).versionName
    }.getOrNull()

    fun get(): DeviceProfile {
        val patch = Build.VERSION.SECURITY_PATCH?.let { 
            runCatching { LocalDate.parse(it) }.getOrNull() 
        }
        return DeviceProfile(
            manufacturer = Build.MANUFACTURER.orEmpty(),
            model = Build.MODEL.orEmpty(),
            sdkInt = Build.VERSION.SDK_INT,
            securityPatch = patch,
            chromeVersion = pkgVersion("com.android.chrome"),
            webViewVersion = pkgVersion("com.google.android.webview") ?: pkgVersion("com.android.webview")
        )
    }
}