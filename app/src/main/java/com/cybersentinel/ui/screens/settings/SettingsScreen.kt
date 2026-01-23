package com.cybersentinel.ui.screens.settings

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel

/**
 * Settings screen pro CyberSentinel aplikaci
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    viewModel: SettingsViewModel = hiltViewModel()
) {
    val isDarkTheme by viewModel.isDarkTheme.collectAsState()
    val notificationsEnabled by viewModel.notificationsEnabled.collectAsState()
    val cveNotifications by viewModel.cveNotifications.collectAsState()
    val autoRefresh by viewModel.autoRefresh.collectAsState()
    val refreshInterval by viewModel.refreshInterval.collectAsState()
    val qrSensitivity by viewModel.qrSensitivity.collectAsState()
    val wifiScanInterval by viewModel.wifiScanInterval.collectAsState()
    val wifiAutoScan by viewModel.wifiAutoScan.collectAsState()
    val hibpApiEnabled by viewModel.hibpApiEnabled.collectAsState()
    val passwordHistory by viewModel.passwordHistory.collectAsState()
    val debugMode by viewModel.debugMode.collectAsState()
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Nastavení") }
            )
        }
    ) { paddingValues ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            item {
                SettingsSection(title = "Vzhled") {
                    SettingsItem(
                        title = "Tmavý režim",
                        subtitle = "Přepnout mezi světlým a tmavým tématem",
                        icon = Icons.Default.DarkMode,
                        trailing = {
                            Switch(
                                checked = isDarkTheme,
                                onCheckedChange = { viewModel.toggleDarkTheme() }
                            )
                        }
                    )
                }
            }
            
            item {
                SettingsSection(title = "Notifikace") {
                    SettingsItem(
                        title = "Povolit notifikace",
                        subtitle = "Globální nastavení notifikací",
                        icon = Icons.Default.Notifications,
                        trailing = {
                            Switch(
                                checked = notificationsEnabled,
                                onCheckedChange = { viewModel.toggleNotifications() }
                            )
                        }
                    )
                    
                    if (notificationsEnabled) {
                        SettingsItem(
                            title = "CVE upozornění",
                            subtitle = "Notifikace o nových kritických CVE",
                            icon = Icons.Default.Security,
                            trailing = {
                                Switch(
                                    checked = cveNotifications,
                                    onCheckedChange = { viewModel.toggleCveNotifications() }
                                )
                            }
                        )
                    }
                }
            }
            
            item {
                SettingsSection(title = "CVE Monitor") {
                    SettingsItem(
                        title = "Automatické obnovení",
                        subtitle = "Automaticky aktualizovat CVE data",
                        icon = Icons.Default.Autorenew,
                        trailing = {
                            Switch(
                                checked = autoRefresh,
                                onCheckedChange = { viewModel.toggleAutoRefresh() }
                            )
                        }
                    )
                    
                    if (autoRefresh) {
                        SettingsItem(
                            title = "Interval obnovení",
                            subtitle = "$refreshInterval hodin",
                            icon = Icons.Default.Schedule,
                            trailing = {
                                OutlinedButton(
                                    onClick = { /* TODO: Show time picker */ }
                                ) {
                                    Text("${refreshInterval}h")
                                }
                            }
                        )
                    }
                }
            }
            
            item {
                SettingsSection(title = "QR Scanner") {
                    SettingsItem(
                        title = "Citlivost detekce",
                        subtitle = when (qrSensitivity) {
                            0 -> "Velmi nízká"
                            1 -> "Nízká"
                            2 -> "Střední"
                            3 -> "Vysoká"
                            4 -> "Velmi vysoká"
                            else -> "Střední"
                        },
                        icon = Icons.Default.QrCodeScanner
                    )
                    
                    Slider(
                        value = qrSensitivity.toFloat(),
                        onValueChange = { viewModel.setQrSensitivity(it.toInt()) },
                        valueRange = 0f..4f,
                        steps = 3,
                        modifier = Modifier.padding(horizontal = 16.dp)
                    )
                }
            }
            
            item {
                SettingsSection(title = "Wi-Fi Auditor") {
                    SettingsItem(
                        title = "Interval skenování",
                        subtitle = "$wifiScanInterval sekund",
                        icon = Icons.Default.Wifi,
                        trailing = {
                            OutlinedButton(
                                onClick = { /* TODO: Show number picker */ }
                            ) {
                                Text("${wifiScanInterval}s")
                            }
                        }
                    )
                    
                    SettingsItem(
                        title = "Automatické skenování",
                        subtitle = "Pravidelně skenovat Wi-Fi sítě",
                        icon = Icons.Default.WifiTethering,
                        trailing = {
                            Switch(
                                checked = wifiAutoScan,
                                onCheckedChange = { viewModel.toggleWifiAutoScan() }
                            )
                        }
                    )
                }
            }
            
            item {
                SettingsSection(title = "HIBP Password Check") {
                    SettingsItem(
                        title = "HIBP API",
                        subtitle = "Povolit kontrolu přes Have I Been Pwned",
                        icon = Icons.Default.Password,
                        trailing = {
                            Switch(
                                checked = hibpApiEnabled,
                                onCheckedChange = { viewModel.toggleHibpApi() }
                            )
                        }
                    )
                    
                    SettingsItem(
                        title = "Historie hesel",
                        subtitle = "Ukládat kontrolovaná hesla lokálně",
                        icon = Icons.Default.History,
                        trailing = {
                            Switch(
                                checked = passwordHistory,
                                onCheckedChange = { viewModel.togglePasswordHistory() }
                            )
                        }
                    )
                }
            }
            
            item {
                SettingsSection(title = "O aplikaci") {
                    SettingsItem(
                        title = "Verze",
                        subtitle = "CyberSentinel v1.0.0",
                        icon = Icons.Default.Info,
                        onClick = { /* TODO: Show version info */ }
                    )
                    
                    SettingsItem(
                        title = "Licence",
                        subtitle = "Zobrazit open source licence",
                        icon = Icons.Default.Description,
                        onClick = { /* TODO: Show licenses */ }
                    )
                    
                    SettingsItem(
                        title = "Zdroj kódu",
                        subtitle = "GitHub repository",
                        icon = Icons.Default.Code,
                        onClick = { /* TODO: Open GitHub */ }
                    )
                    
                    SettingsItem(
                        title = "Podmínky použití",
                        subtitle = "Právní informace",
                        icon = Icons.Default.Gavel,
                        onClick = { /* TODO: Show terms */ }
                    )
                }
            }
            
            item {
                SettingsSection(title = "Pokročilé") {
                    SettingsItem(
                        title = "Vymazat cache",
                        subtitle = "Smazat dočasné soubory a cache",
                        icon = Icons.Default.CleaningServices,
                        onClick = { viewModel.clearCache() }
                    )
                    
                    SettingsItem(
                        title = "Exportovat nastavení",
                        subtitle = "Zálohovat konfiguraci",
                        icon = Icons.Default.FileDownload,
                        onClick = { viewModel.exportSettings() }
                    )
                    
                    SettingsItem(
                        title = "Obnovit výchozí",
                        subtitle = "Reset všech nastavení",
                        icon = Icons.Default.RestoreFromTrash,
                        onClick = { viewModel.resetAllSettings() }
                    )
                    
                    if (debugMode) {
                        SettingsItem(
                            title = "Debug režim",
                            subtitle = "Vývojářské nastavení",
                            icon = Icons.Default.BugReport,
                            trailing = {
                                Switch(
                                    checked = debugMode,
                                    onCheckedChange = { viewModel.toggleDebugMode() }
                                )
                            }
                        )
                    }
                }
            }
            
            item {
                Spacer(modifier = Modifier.height(32.dp))
                
                // App info footer
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.primaryContainer
                    )
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            text = "🛡️ CyberSentinel",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.onPrimaryContainer
                        )
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        Text(
                            text = "Komprehenzivní bezpečnostní suite pro Android",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onPrimaryContainer
                        )
                        
                        Spacer(modifier = Modifier.height(4.dp))
                        
                        Text(
                            text = "CVE Monitor • PhishGuard • Wi-Fi Auditor • HIBP Check",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onPrimaryContainer
                        )
                    }
                }
            }
        }
    }
}

/**
 * Settings section wrapper
 */
@Composable
private fun SettingsSection(
    title: String,
    content: @Composable ColumnScope.() -> Unit
) {
    Column {
        Text(
            text = title,
            style = MaterialTheme.typography.titleSmall,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
        )
        
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surface
            )
        ) {
            Column {
                content()
            }
        }
    }
}

/**
 * Individual settings item
 */
@Composable
private fun SettingsItem(
    title: String,
    subtitle: String? = null,
    icon: ImageVector,
    trailing: @Composable (() -> Unit)? = null,
    onClick: (() -> Unit)? = null
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .let { modifier ->
                if (onClick != null) {
                    modifier.clickable { onClick() }
                } else {
                    modifier
                }
            }
            .padding(16.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            modifier = Modifier.size(24.dp),
            tint = MaterialTheme.colorScheme.onSurfaceVariant
        )
        
        Spacer(modifier = Modifier.width(16.dp))
        
        Column(
            modifier = Modifier.weight(1f)
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Medium
            )
            
            subtitle?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        
        trailing?.invoke()
    }
}