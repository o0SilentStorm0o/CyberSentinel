package com.cybersentinel.app.ui.screens.appscan

import android.util.Log
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.cybersentinel.app.domain.security.AppSecurityScanner.*
import com.cybersentinel.app.domain.security.BaselineManager
import com.cybersentinel.app.domain.security.RiskLabels
import com.cybersentinel.app.domain.security.TrustEvidenceEngine
import com.cybersentinel.app.domain.security.TrustRiskModel

private const val TAG = "AppScanScreen"

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppScanScreen(
    viewModel: AppScanViewModel = hiltViewModel(),
    onNavigateBack: () -> Unit = {},
    onNavigateToAppDetail: (String) -> Unit = {}
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    
    // Debug logging
    LaunchedEffect(uiState.isScanning, uiState.reports.size, uiState.filter) {
        Log.d(TAG, "UI State: isScanning=${uiState.isScanning}, " +
            "reports=${uiState.reports.size}, filter=${uiState.filter}, " +
            "error=${uiState.error}, summary=${uiState.summary != null}")
    }
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Bezpečnost aplikací") },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Zpět")
                    }
                },
                actions = {
                    if (!uiState.isScanning) {
                        IconButton(onClick = { viewModel.startScan() }) {
                            Icon(Icons.Default.Refresh, "Znovu skenovat")
                        }
                    }
                    IconButton(onClick = { viewModel.toggleSystemApps() }) {
                        Icon(
                            if (uiState.includeSystemApps) Icons.Default.VisibilityOff 
                            else Icons.Default.Visibility,
                            if (uiState.includeSystemApps) "Skrýt systémové" else "Zobrazit systémové"
                        )
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            // Summary card (always visible when scan complete)
            if (!uiState.isScanning && uiState.summary != null) {
                ScanSummaryCard(summary = uiState.summary!!)
            }
            
            // Scanning progress
            if (uiState.isScanning) {
                ScanningProgress(
                    progress = uiState.scanProgress,
                    currentApp = uiState.currentScanningApp
                )
            }
            
            // Filter chips
            if (!uiState.isScanning && uiState.reports.isNotEmpty()) {
                FilterChipRow(
                    selectedFilter = uiState.filter,
                    onFilterChange = { viewModel.setFilter(it) },
                    summary = uiState.summary
                )
            }
            
            // Results list - takes remaining space
            when {
                uiState.isScanning -> {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .weight(1f),
                        contentAlignment = Alignment.Center
                    ) {
                        CircularProgressIndicator()
                    }
                }
                uiState.reports.isEmpty() -> {
                    Box(modifier = Modifier.weight(1f)) {
                        EmptyState(onStartScan = { viewModel.startScan() })
                    }
                }
                else -> {
                    // Separate user apps and system apps
                    val userReports = uiState.reports.filter { !it.app.isSystemApp }
                    val systemReports = uiState.reports.filter { it.app.isSystemApp }

                    val filteredUserReports = when (uiState.filter) {
                        AppFilter.ALL -> userReports
                        AppFilter.CRITICAL -> userReports.filter { 
                            it.verdict.effectiveRisk == TrustRiskModel.EffectiveRisk.CRITICAL 
                        }
                        AppFilter.NEEDS_ATTENTION -> userReports.filter { 
                            it.verdict.effectiveRisk == TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION 
                        }
                        AppFilter.INFO -> userReports.filter { 
                            it.verdict.effectiveRisk == TrustRiskModel.EffectiveRisk.INFO 
                        }
                        AppFilter.SAFE -> userReports.filter { 
                            it.verdict.effectiveRisk == TrustRiskModel.EffectiveRisk.SAFE 
                        }
                    }
                    
                    Log.d(TAG, "LazyColumn: userReports=${filteredUserReports.size}, " +
                        "systemReports=${systemReports.size}, " +
                        "first3=${filteredUserReports.take(3).map { it.app.appName }}")
                    
                    if (filteredUserReports.isEmpty() && systemReports.isEmpty()) {
                        // Show empty filter state
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .weight(1f),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = "Žádné aplikace v tomto filtru",
                                style = MaterialTheme.typography.bodyLarge,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    } else {
                        LazyColumn(
                            modifier = Modifier
                                .fillMaxWidth()
                                .weight(1f),
                            contentPadding = PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp)
                        ) {
                            // ── User apps section ──
                            if (filteredUserReports.isNotEmpty()) {
                                items(
                                    items = filteredUserReports,
                                    key = { it.app.packageName }
                                ) { report ->
                                    AppReportCard(
                                        report = report,
                                        onClick = { onNavigateToAppDetail(report.app.packageName) }
                                    )
                                }
                            } else if (userReports.isEmpty()) {
                                item {
                                    Text(
                                        text = "Žádné uživatelské aplikace v tomto filtru",
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        modifier = Modifier.padding(vertical = 8.dp)
                                    )
                                }
                            }

                            // ── System apps section (only when system apps are included) ──
                            if (systemReports.isNotEmpty() && uiState.includeSystemApps) {
                                item {
                                    SystemAppsSectionHeader(
                                        systemReports = systemReports,
                                        expanded = uiState.systemSectionExpanded,
                                        onToggle = { viewModel.toggleSystemSection() }
                                    )
                                }
                                
                                if (uiState.systemSectionExpanded) {
                                    // Show only top-N with highest risk, capped at 20
                                    val topSystemApps = systemReports
                                        .filter { 
                                            it.verdict.effectiveRisk != TrustRiskModel.EffectiveRisk.SAFE 
                                        }
                                        .sortedByDescending { it.overallRisk.score }
                                        .take(20)
                                    
                                    items(
                                        items = topSystemApps,
                                        key = { it.app.packageName }
                                    ) { report ->
                                        AppReportCard(
                                            report = report,
                                            onClick = { onNavigateToAppDetail(report.app.packageName) }
                                        )
                                    }
                                    
                                    if (topSystemApps.isEmpty()) {
                                        item {
                                            Text(
                                                text = "✅ Žádné systémové komponenty s nálezy",
                                                style = MaterialTheme.typography.bodyMedium,
                                                color = Color(0xFF4CAF50),
                                                modifier = Modifier.padding(vertical = 8.dp, horizontal = 4.dp)
                                            )
                                        }
                                    }
                                }
                            }
                            
                            item {
                                Spacer(Modifier.height(80.dp))
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ScanningProgress(
    progress: Float,
    currentApp: String?
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            CircularProgressIndicator(
                progress = { progress },
                modifier = Modifier.size(64.dp),
                strokeWidth = 6.dp
            )
            
            Spacer(Modifier.height(16.dp))
            
            Text(
                text = "Skenování aplikací...",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
            
            Text(
                text = "${(progress * 100).toInt()}%",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )
            
            currentApp?.let {
                Spacer(Modifier.height(8.dp))
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
    }
}

@Composable
private fun ScanSummaryCard(summary: ScanSummary) {
    val hasIssues = summary.criticalRiskApps > 0 || summary.highRiskApps > 0
    
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        colors = if (hasIssues) CardDefaults.cardColors() 
                 else CardDefaults.cardColors(containerColor = Color(0xFF4CAF50).copy(alpha = 0.1f))
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            // User-friendly headline
            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = if (hasIssues) Icons.Default.Info else Icons.Default.CheckCircle,
                    contentDescription = null,
                    tint = if (hasIssues) MaterialTheme.colorScheme.primary else Color(0xFF4CAF50),
                    modifier = Modifier.size(24.dp)
                )
                Spacer(Modifier.width(12.dp))
                Text(
                    text = if (hasIssues) 
                        "Některé aplikace vyžadují vaši pozornost"
                    else 
                        "Vaše aplikace jsou v pořádku",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
            }
            
            Spacer(Modifier.height(8.dp))
            
            // Human-readable summary
            Text(
                text = buildString {
                    append("Zkontrolovali jsme ${summary.totalAppsScanned} aplikací. ")
                    if (summary.criticalRiskApps > 0) {
                        append("${summary.criticalRiskApps} vyžaduje okamžitou pozornost. ")
                    }
                    if (summary.highRiskApps > 0) {
                        append("${summary.highRiskApps} doporučujeme zkontrolovat. ")
                    }
                    if (summary.safeApps > 0 && !hasIssues) {
                        append("Všechny aplikace splňují bezpečnostní standardy.")
                    }
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            
            Spacer(Modifier.height(16.dp))
            
            // Stats row - simplified
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                if (summary.criticalRiskApps + summary.highRiskApps > 0) {
                    StatItem(
                        value = (summary.criticalRiskApps + summary.highRiskApps).toString(),
                        label = "Ke kontrole",
                        icon = Icons.Default.Warning,
                        color = Color(0xFFFF9800)
                    )
                }
                StatItem(
                    value = summary.safeApps.toString(),
                    label = "V pořádku",
                    icon = Icons.Default.CheckCircle,
                    color = Color(0xFF4CAF50)
                )
                StatItem(
                    value = summary.totalAppsScanned.toString(),
                    label = "Celkem",
                    icon = Icons.Default.Apps,
                    color = MaterialTheme.colorScheme.primary
                )
            }
            
            // Privacy hint if over-privileged apps found
            if (summary.overPrivilegedApps > 0) {
                Spacer(Modifier.height(12.dp))
                HorizontalDivider()
                Spacer(Modifier.height(12.dp))
                
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            Color(0xFFFF9800).copy(alpha = 0.1f),
                            RoundedCornerShape(8.dp)
                        )
                        .padding(12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Default.PrivacyTip,
                        contentDescription = null,
                        tint = Color(0xFFFF9800),
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(Modifier.width(12.dp))
                    Text(
                        text = "${summary.overPrivilegedApps} aplikací má více oprávnění, než pravděpodobně potřebuje",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }
        }
    }
}

@Composable
private fun StatItem(
    value: String,
    label: String,
    icon: ImageVector,
    color: Color
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = color,
            modifier = Modifier.size(28.dp)
        )
        Spacer(Modifier.height(4.dp))
        Text(
            text = value,
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold,
            color = color
        )
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun WarningChip(text: String, color: Color) {
    Surface(
        color = color.copy(alpha = 0.1f),
        shape = RoundedCornerShape(16.dp)
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Default.Warning,
                contentDescription = null,
                tint = color,
                modifier = Modifier.size(16.dp)
            )
            Spacer(Modifier.width(6.dp))
            Text(
                text = text,
                style = MaterialTheme.typography.labelMedium,
                color = color
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FilterChipRow(
    selectedFilter: AppFilter,
    onFilterChange: (AppFilter) -> Unit,
    summary: ScanSummary?
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        AppFilter.entries.forEach { filter ->
            val count = summary?.let {
                when (filter) {
                    AppFilter.ALL -> it.totalAppsScanned
                    AppFilter.CRITICAL -> it.criticalRiskApps
                    AppFilter.NEEDS_ATTENTION -> it.highRiskApps
                    AppFilter.INFO -> it.mediumRiskApps
                    AppFilter.SAFE -> it.safeApps
                }
            }
            
            FilterChip(
                selected = selectedFilter == filter,
                onClick = { onFilterChange(filter) },
                label = { 
                    Text(
                        if (count != null && count > 0) "${filter.label} ($count)" 
                        else filter.label
                    ) 
                },
                leadingIcon = if (selectedFilter == filter) {
                    { Icon(Icons.Default.Check, null, Modifier.size(18.dp)) }
                } else null
            )
        }
    }
}

@Composable
private fun AppReportCard(
    report: AppSecurityReport,
    onClick: () -> Unit
) {
    val context = LocalContext.current
    var expanded by remember { mutableStateOf(false) }
    
    // Use 4-state verdict labels
    val riskLabel = RiskLabels.getVerdictLabel(report.verdict.effectiveRisk)
    val riskColor = Color(riskLabel.color.toInt())
    
    // Use secure trust verification (packageName + SHA-256 cert)
    val isTrusted = report.trustVerification.isTrusted
    val developerName = report.trustVerification.developerName
    val trustLevel = report.trustEvidence.trustLevel
    val trustBadge = when (trustLevel) {
        TrustEvidenceEngine.TrustLevel.HIGH -> "✅"
        TrustEvidenceEngine.TrustLevel.MODERATE -> "🟡"
        TrustEvidenceEngine.TrustLevel.LOW -> "⚠️"
        TrustEvidenceEngine.TrustLevel.ANOMALOUS -> "🚨"
    }
    
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 2.dp),
        onClick = { expanded = !expanded }
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp)
        ) {
            // Compact header row
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Risk indicator dot
                Box(
                    modifier = Modifier
                        .size(10.dp)
                        .clip(CircleShape)
                        .background(riskColor)
                )
                
                Spacer(Modifier.width(10.dp))
                
                // App name
                Text(
                    text = report.app.appName,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
                
                Spacer(Modifier.width(8.dp))
                
                // Risk badge
                Text(
                    text = riskLabel.badge,
                    style = MaterialTheme.typography.labelSmall,
                    color = riskColor
                )
                
                // Trust badge
                Text(
                    text = trustBadge,
                    style = MaterialTheme.typography.labelSmall,
                    modifier = Modifier.padding(start = 4.dp)
                )
                
                // Expand icon
                Icon(
                    imageVector = if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            
            // Main concern (one-liner under the name)
            val mainConcern = when {
                report.baselineComparison.anomalies.any { 
                    it.type == BaselineManager.AnomalyType.CERT_CHANGED 
                } -> "⚠️ Změna podpisu od posledního skenování!"
                report.signatureAnalysis.isDebugSigned -> "Může jít o neoficiální verzi"
                report.nativeLibAnalysis.hasSuspiciousLibs -> "Obsahuje neobvyklý kód"
                report.permissionAnalysis.isOverPrivileged -> "Má více oprávnění než potřebuje"
                report.app.targetSdk in 1..28 -> "Navržena pro starší Android"
                report.issues.isNotEmpty() -> riskLabel.shortDescription
                isTrusted && developerName != null -> "Ověřeno: $developerName"
                else -> null
            }
            
            mainConcern?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(start = 20.dp, top = 2.dp)
                )
            }
            
            // Expanded details
            if (expanded) {
                Spacer(Modifier.height(8.dp))
                HorizontalDivider()
                Spacer(Modifier.height(8.dp))
                
                // Granted dangerous permissions
                val grantedPerms = report.permissionAnalysis.dangerousPermissions.filter { it.isGranted }
                if (grantedPerms.isNotEmpty()) {
                    Text(
                        text = "K čemu má aplikace přístup",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    Spacer(Modifier.height(4.dp))
                    
                    grantedPerms.take(5).forEach { perm ->
                        Row(
                            modifier = Modifier.padding(vertical = 2.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = perm.category.icon,
                                modifier = Modifier.width(24.dp)
                            )
                            Text(
                                text = "${perm.shortName} — ${perm.description}",
                                style = MaterialTheme.typography.bodySmall,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis,
                                modifier = Modifier.weight(1f)
                            )
                        }
                    }
                    
                    val remaining = grantedPerms.size - 5
                    if (remaining > 0) {
                        Text(
                            text = "… a $remaining dalších",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(start = 24.dp)
                        )
                    }
                }
                
                // Issues
                if (report.issues.isNotEmpty()) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = "Co doporučujeme zkontrolovat",
                        style = MaterialTheme.typography.labelMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    Spacer(Modifier.height(4.dp))
                    
                    report.issues.take(3).forEach { issue ->
                        Row(
                            modifier = Modifier.padding(vertical = 2.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(
                                modifier = Modifier
                                    .size(6.dp)
                                    .clip(CircleShape)
                                    .background(Color(issue.severity.color.toInt()))
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(
                                text = issue.title,
                                style = MaterialTheme.typography.bodySmall,
                                modifier = Modifier.weight(1f)
                            )
                        }
                    }
                }
                
                // Trust & Verdict info
                Spacer(Modifier.height(8.dp))
                val verdictLabel = when (report.verdict.effectiveRisk) {
                    TrustRiskModel.EffectiveRisk.CRITICAL -> "🔴 Vyžaduje pozornost"
                    TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION -> "🟠 Ke kontrole"
                    TrustRiskModel.EffectiveRisk.INFO -> "� Informace"
                    TrustRiskModel.EffectiveRisk.SAFE -> "🟢 Bezpečná"
                }
                val trustLabel = when (trustLevel) {
                    TrustEvidenceEngine.TrustLevel.HIGH -> "Vysoká důvěra"
                    TrustEvidenceEngine.TrustLevel.MODERATE -> "Střední důvěra"
                    TrustEvidenceEngine.TrustLevel.LOW -> "Nízká důvěra"
                    TrustEvidenceEngine.TrustLevel.ANOMALOUS -> "Podezřelé"
                }
                val installerLabel = when (report.trustEvidence.installerInfo.installerType) {
                    TrustEvidenceEngine.InstallerType.PLAY_STORE -> "Google Play"
                    TrustEvidenceEngine.InstallerType.SAMSUNG_STORE -> "Galaxy Store"
                    TrustEvidenceEngine.InstallerType.HUAWEI_APPGALLERY -> "AppGallery"
                    TrustEvidenceEngine.InstallerType.AMAZON_APPSTORE -> "Amazon"
                    TrustEvidenceEngine.InstallerType.SYSTEM_INSTALLER -> "Předinstalováno"
                    TrustEvidenceEngine.InstallerType.MDM_INSTALLER -> "MDM"
                    TrustEvidenceEngine.InstallerType.SIDELOADED -> "Sideload"
                    TrustEvidenceEngine.InstallerType.UNKNOWN -> "Neznámý"
                }
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(verdictLabel, style = MaterialTheme.typography.labelSmall)
                    Text("$trustBadge $trustLabel", style = MaterialTheme.typography.labelSmall)
                    Text("📦 $installerLabel", style = MaterialTheme.typography.labelSmall)
                }
                
                // Tech details row
                Spacer(Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text("SDK ${report.app.targetSdk}", style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(report.signatureAnalysis.signatureScheme, style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(formatSize(report.app.apkSizeBytes), style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SystemAppsSectionHeader(
    systemReports: List<AppSecurityReport>,
    expanded: Boolean,
    onToggle: () -> Unit
) {
    val critical = systemReports.count {
        it.verdict.effectiveRisk == TrustRiskModel.EffectiveRisk.CRITICAL
    }
    val needsAttention = systemReports.count {
        it.verdict.effectiveRisk == TrustRiskModel.EffectiveRisk.NEEDS_ATTENTION
    }
    val safe = systemReports.count {
        it.verdict.effectiveRisk == TrustRiskModel.EffectiveRisk.SAFE
    }
    val info = systemReports.count {
        it.verdict.effectiveRisk == TrustRiskModel.EffectiveRisk.INFO
    }

    val summaryParts = mutableListOf<String>()
    if (critical > 0) summaryParts.add("🔴 $critical kritických")
    if (needsAttention > 0) summaryParts.add("🟠 $needsAttention ke kontrole")
    if (info > 0) summaryParts.add("ℹ️ $info info")
    summaryParts.add("🟢 $safe bezpečných")
    val summaryText = summaryParts.joinToString("  ·  ")

    Card(
        onClick = onToggle,
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
        ),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Default.PhoneAndroid,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = "Systémové komponenty (${systemReports.size})",
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold
                    )
                }
                Icon(
                    imageVector = if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    contentDescription = if (expanded) "Sbalit" else "Rozbalit",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Spacer(Modifier.height(4.dp))
            Text(
                text = summaryText,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun EmptyState(onStartScan: () -> Unit) {
    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(
                imageVector = Icons.Default.Security,
                contentDescription = null,
                modifier = Modifier.size(80.dp),
                tint = MaterialTheme.colorScheme.primary.copy(alpha = 0.5f)
            )
            Spacer(Modifier.height(16.dp))
            Text(
                text = "Žádné výsledky skenování",
                style = MaterialTheme.typography.titleMedium
            )
            Text(
                text = "Spusťte skenování pro analýzu nainstalovaných aplikací",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(Modifier.height(24.dp))
            Button(onClick = onStartScan) {
                Icon(Icons.Default.PlayArrow, null)
                Spacer(Modifier.width(8.dp))
                Text("Spustit skenování")
            }
        }
    }
}

private fun formatSize(bytes: Long): String {
    return when {
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> "${bytes / 1024} KB"
        bytes < 1024 * 1024 * 1024 -> "${bytes / (1024 * 1024)} MB"
        else -> "${"%.1f".format(bytes / (1024.0 * 1024.0 * 1024.0))} GB"
    }
}

enum class AppFilter(val label: String) {
    ALL("Vše"),
    CRITICAL("Vyžaduje pozornost"),
    NEEDS_ATTENTION("Ke kontrole"),
    INFO("Informace"),
    SAFE("Bezpečné")
}
