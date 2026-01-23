package com.cybersentinel.ui.screens.wifi

import android.Manifest
import android.content.Context
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import androidx.annotation.RequiresPermission
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.google.accompanist.permissions.ExperimentalPermissionsApi
import com.google.accompanist.permissions.rememberMultiplePermissionsState
import kotlinx.coroutines.delay

/**
 * Wi-Fi Security Auditor - skenuje a analyzuje bezpečnost Wi-Fi sítí
 */
@OptIn(ExperimentalPermissionsApi::class, ExperimentalMaterial3Api::class)
@Composable
fun WifiAuditorScreenImpl() {
    val context = LocalContext.current
    val wifiManager = remember { context.getSystemService(Context.WIFI_SERVICE) as WifiManager }
    
    val permissions = rememberMultiplePermissionsState(
        permissions = listOf(
            Manifest.permission.ACCESS_WIFI_STATE,
            Manifest.permission.CHANGE_WIFI_STATE,
            Manifest.permission.ACCESS_FINE_LOCATION
        )
    )
    
    var scanResults by remember { mutableStateOf<List<WifiSecurityInfo>>(emptyList()) }
    var isScanning by remember { mutableStateOf(false) }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Wi-Fi Security Auditor") },
                actions = {
                    IconButton(
                        onClick = {
                            if (permissions.allPermissionsGranted) {
                                isScanning = true
                                scanResults = performWifiScan(wifiManager)
                                isScanning = false
                            } else {
                                permissions.launchMultiplePermissionRequest()
                            }
                        }
                    ) {
                        Icon(
                            imageVector = if (isScanning) Icons.Default.HourglassEmpty else Icons.Default.Refresh,
                            contentDescription = "Scan Wi-Fi networks"
                        )
                    }
                }
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .padding(16.dp)
        ) {
            if (!permissions.allPermissionsGranted) {
                PermissionRequestCard(
                    onRequestPermissions = { permissions.launchMultiplePermissionRequest() }
                )
            } else {
                // Scanning status
                if (isScanning) {
                    ScanningIndicator()
                } else if (scanResults.isEmpty()) {
                    EmptyStateCard()
                } else {
                    // Results summary
                    SecuritySummaryCard(scanResults)
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    // Network list
                    Text(
                        text = "Nalezené sítě (${scanResults.size})",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    LazyColumn(
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        items(scanResults) { network ->
                            WifiNetworkCard(network = network)
                        }
                    }
                }
            }
        }
    }
}

/**
 * Provádí Wi-Fi scan a analyzuje bezpečnost
 */
@RequiresPermission(allOf = [
    Manifest.permission.ACCESS_WIFI_STATE,
    Manifest.permission.ACCESS_FINE_LOCATION
])
private fun performWifiScan(wifiManager: WifiManager): List<WifiSecurityInfo> {
    return try {
        wifiManager.startScan()
        val results = wifiManager.scanResults
        
        results.map { scanResult ->
            analyzeWifiSecurity(scanResult)
        }.sortedByDescending { it.signalStrength }
        
    } catch (e: Exception) {
        emptyList()
    }
}

/**
 * Analyzuje bezpečnost Wi-Fi sítě
 */
private fun analyzeWifiSecurity(scanResult: ScanResult): WifiSecurityInfo {
    val capabilities = scanResult.capabilities.uppercase()
    
    val securityType = when {
        capabilities.contains("WPA3") -> WifiSecurityType.WPA3
        capabilities.contains("WPA2") -> WifiSecurityType.WPA2
        capabilities.contains("WPA") -> WifiSecurityType.WPA
        capabilities.contains("WEP") -> WifiSecurityType.WEP
        else -> WifiSecurityType.OPEN
    }
    
    val riskLevel = when (securityType) {
        WifiSecurityType.WPA3 -> SecurityRisk.LOW
        WifiSecurityType.WPA2 -> SecurityRisk.LOW
        WifiSecurityType.WPA -> SecurityRisk.MEDIUM
        WifiSecurityType.WEP -> SecurityRisk.HIGH
        WifiSecurityType.OPEN -> SecurityRisk.CRITICAL
    }
    
    val recommendations = generateRecommendations(securityType, scanResult)
    
    return WifiSecurityInfo(
        ssid = scanResult.SSID?.removeSurrounding("\"") ?: "Hidden Network",
        bssid = scanResult.BSSID,
        securityType = securityType,
        signalStrength = WifiManager.calculateSignalLevel(scanResult.level, 4),
        frequency = scanResult.frequency,
        isHidden = scanResult.SSID.isNullOrEmpty(),
        riskLevel = riskLevel,
        recommendations = recommendations
    )
}

/**
 * Generuje doporučení pro zabezpečení
 */
private fun generateRecommendations(
    securityType: WifiSecurityType,
    scanResult: ScanResult
): List<String> {
    val recommendations = mutableListOf<String>()
    
    when (securityType) {
        WifiSecurityType.OPEN -> {
            recommendations.add("⚠️ Otevřená síť - data nejsou šifrována")
            recommendations.add("🚫 Nepřipojujte se bez VPN")
            recommendations.add("🔒 Použijte mobilní data nebo zabezpečenou síť")
        }
        WifiSecurityType.WEP -> {
            recommendations.add("⚠️ WEP je zastaralý a snadno prolomitelný")
            recommendations.add("🔄 Doporučujeme upgrade na WPA2/WPA3")
            recommendations.add("🛡️ Používejte pouze pro nekritické aktivity")
        }
        WifiSecurityType.WPA -> {
            recommendations.add("⚠️ WPA má známé vulnerabilities")
            recommendations.add("🔄 Doporučujeme upgrade na WPA2/WPA3")
        }
        WifiSecurityType.WPA2 -> {
            recommendations.add("✅ Dobrá úroveň zabezpečení")
            recommendations.add("🔄 Zvažte upgrade na WPA3 pokud je dostupná")
        }
        WifiSecurityType.WPA3 -> {
            recommendations.add("✅ Nejvyšší úroveň zabezpečení")
            recommendations.add("🛡️ Bezpečné pro všechny aktivity")
        }
    }
    
    if (scanResult.frequency > 5000) {
        recommendations.add("📡 5GHz síť - lepší výkon, kratší dosah")
    }
    
    return recommendations
}

/**
 * Data class pro informace o Wi-Fi síti
 */
data class WifiSecurityInfo(
    val ssid: String,
    val bssid: String,
    val securityType: WifiSecurityType,
    val signalStrength: Int, // 0-4
    val frequency: Int,
    val isHidden: Boolean,
    val riskLevel: SecurityRisk,
    val recommendations: List<String>
)

/**
 * Typy Wi-Fi zabezpečení
 */
enum class WifiSecurityType(val displayName: String) {
    OPEN("Otevřená"),
    WEP("WEP"),
    WPA("WPA"),
    WPA2("WPA2"),
    WPA3("WPA3")
}

/**
 * Úrovně bezpečnostního rizika
 */
enum class SecurityRisk(val displayName: String, val color: Color) {
    LOW("Nízké", Color(0xFF4CAF50)),
    MEDIUM("Střední", Color(0xFFFF9800)),
    HIGH("Vysoké", Color(0xFFFF5722)),
    CRITICAL("Kritické", Color(0xFFF44336))
}

/**
 * Karta pro žádost o oprávnění
 */
@Composable
private fun PermissionRequestCard(onRequestPermissions: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(
                imageVector = Icons.Default.Warning,
                contentDescription = null,
                modifier = Modifier.size(48.dp),
                tint = MaterialTheme.colorScheme.onErrorContainer
            )
            
            Spacer(modifier = Modifier.height(16.dp))
            
            Text(
                text = "Potřebná oprávnění",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
            
            Spacer(modifier = Modifier.height(8.dp))
            
            Text(
                text = "Pro audit Wi-Fi sítí jsou potřeba oprávnění pro přístup k Wi-Fi a poloze",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
            
            Spacer(modifier = Modifier.height(16.dp))
            
            Button(
                onClick = onRequestPermissions,
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.primary
                )
            ) {
                Text("Povolit oprávnění")
            }
        }
    }
}

/**
 * Scanning indicator
 */
@Composable
private fun ScanningIndicator() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer
        )
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            CircularProgressIndicator(
                modifier = Modifier.size(32.dp),
                color = MaterialTheme.colorScheme.onPrimaryContainer
            )
            
            Spacer(modifier = Modifier.width(16.dp))
            
            Text(
                text = "Skenování Wi-Fi sítí...",
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onPrimaryContainer
            )
        }
    }
}

/**
 * Empty state card
 */
@Composable
private fun EmptyStateCard() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(
            modifier = Modifier.padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(
                imageVector = Icons.Default.Wifi,
                contentDescription = null,
                modifier = Modifier.size(64.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
            
            Spacer(modifier = Modifier.height(16.dp))
            
            Text(
                text = "Wi-Fi Security Auditor",
                style = MaterialTheme.typography.titleLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            
            Spacer(modifier = Modifier.height(8.dp))
            
            Text(
                text = "Klikněte na ikonu obnovy pro skenování Wi-Fi sítí v okolí",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

/**
 * Security summary card
 */
@Composable
private fun SecuritySummaryCard(networks: List<WifiSecurityInfo>) {
    val riskCounts = networks.groupingBy { it.riskLevel }.eachCount()
    val criticalCount = riskCounts[SecurityRisk.CRITICAL] ?: 0
    val highCount = riskCounts[SecurityRisk.HIGH] ?: 0
    
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (criticalCount > 0 || highCount > 0) {
                MaterialTheme.colorScheme.errorContainer
            } else {
                MaterialTheme.colorScheme.primaryContainer
            }
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Text(
                text = "Bezpečnostní shrnutí",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            
            Spacer(modifier = Modifier.height(12.dp))
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceAround
            ) {
                SecurityRisk.values().forEach { risk ->
                    val count = riskCounts[risk] ?: 0
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            text = count.toString(),
                            style = MaterialTheme.typography.headlineSmall,
                            fontWeight = FontWeight.Bold,
                            color = risk.color
                        )
                        Text(
                            text = risk.displayName,
                            style = MaterialTheme.typography.labelSmall
                        )
                    }
                }
            }
        }
    }
}

/**
 * Individual Wi-Fi network card
 */
@Composable
private fun WifiNetworkCard(network: WifiSecurityInfo) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = network.riskLevel.color.copy(alpha = 0.1f)
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(
                    modifier = Modifier.weight(1f)
                ) {
                    Text(
                        text = if (network.isHidden) "🔒 ${network.ssid}" else network.ssid,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    
                    Text(
                        text = "${network.securityType.displayName} • ${network.frequency}MHz",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                
                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    // Signal strength
                    Icon(
                        imageVector = when (network.signalStrength) {
                            0 -> Icons.Default.SignalWifiOff
                            1 -> Icons.Default.Wifi
                            2 -> Icons.Default.Wifi
                            3 -> Icons.Default.Wifi
                            else -> Icons.Default.Wifi
                        },
                        contentDescription = "Signal strength",
                        modifier = Modifier.size(24.dp)
                    )
                    
                    Spacer(modifier = Modifier.width(8.dp))
                    
                    // Risk badge
                    Surface(
                        shape = RoundedCornerShape(8.dp),
                        color = network.riskLevel.color
                    ) {
                        Text(
                            text = network.riskLevel.displayName,
                            style = MaterialTheme.typography.labelSmall,
                            color = Color.White,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                        )
                    }
                }
            }
            
            if (network.recommendations.isNotEmpty()) {
                Spacer(modifier = Modifier.height(12.dp))
                
                network.recommendations.take(2).forEach { recommendation ->
                    Text(
                        text = recommendation,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(vertical = 1.dp)
                    )
                }
            }
        }
    }
}