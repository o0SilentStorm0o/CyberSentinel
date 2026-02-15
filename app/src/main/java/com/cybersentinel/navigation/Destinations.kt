package com.cybersentinel.navigation

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Wifi
import androidx.compose.ui.graphics.vector.ImageVector

/**
 * Navigační destinace aplikace CyberSentinel
 */
sealed class Screen(
    val route: String,
    val title: String,
    val icon: ImageVector
) {
    object Dashboard : Screen(
        route = "dashboard",
        title = "Security",
        icon = Icons.Default.Shield
    )
    
    object Home : Screen(
        route = "home",
        title = "CVE",
        icon = Icons.Default.Security
    )
    
    object AppScan : Screen(
        route = "app_scan",
        title = "Aplikace",
        icon = Icons.Default.Apps
    )
    
    object QrScanner : Screen(
        route = "qr_scanner",
        title = "QR Scan",
        icon = Icons.Default.QrCodeScanner
    )
    
    object WifiAuditor : Screen(
        route = "wifi_auditor",
        title = "Wi-Fi",
        icon = Icons.Default.Wifi
    )
    
    object PasswordCheck : Screen(
        route = "password_check",
        title = "Hesla",
        icon = Icons.Default.Password
    )
    
    object Settings : Screen(
        route = "settings",
        title = "Nastavení",
        icon = Icons.Default.Settings
    )

    // ── Sprint UI-1: Incident-first screens ──

    object IncidentList : Screen(
        route = "incident_list",
        title = "Incidenty",
        icon = Icons.Default.Notifications
    )

    object IncidentDetail : Screen(
        route = "incident_detail/{eventId}",
        title = "Detail incidentu",
        icon = Icons.Default.Notifications
    ) {
        fun createRoute(eventId: String): String = "incident_detail/$eventId"
    }

    object AiStatus : Screen(
        route = "ai_status",
        title = "AI & Model",
        icon = Icons.Default.Memory
    )
}

/**
 * Seznam všech bottom navigation destinací
 */
val bottomNavScreens = listOf(
    Screen.Dashboard,
    Screen.IncidentList,
    Screen.AppScan,
    Screen.QrScanner,
    Screen.WifiAuditor,
    Screen.Settings
)