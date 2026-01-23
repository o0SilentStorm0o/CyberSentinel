package com.cybersentinel.navigation

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Settings
import androidx.compose.ui.graphics.vector.ImageVector

/**
 * Navigační destinace aplikace CyberSentinel
 */
sealed class Screen(
    val route: String,
    val title: String,
    val icon: ImageVector
) {
    object Home : Screen(
        route = "home",
        title = "CVE Monitor",
        icon = Icons.Default.Security
    )
    
    object QrScanner : Screen(
        route = "qr_scanner",
        title = "PhishGuard",
        icon = Icons.Default.QrCodeScanner
    )
    
    object WifiAuditor : Screen(
        route = "wifi_auditor",
        title = "Wi-Fi Auditor",
        icon = Icons.Default.Wifi
    )
    
    object PasswordCheck : Screen(
        route = "password_check",
        title = "Password Check",
        icon = Icons.Default.Password
    )
    
    object Settings : Screen(
        route = "settings",
        title = "Settings",
        icon = Icons.Default.Settings
    )
}

/**
 * Seznam všech bottom navigation destinací
 */
val bottomNavScreens = listOf(
    Screen.Home,
    Screen.QrScanner,
    Screen.WifiAuditor,
    Screen.PasswordCheck,
    Screen.Settings
)