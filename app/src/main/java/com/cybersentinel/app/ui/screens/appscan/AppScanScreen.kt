package com.cybersentinel.app.ui.screens.appscan

import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
import com.cybersentinel.app.domain.security.RiskLabels
import com.cybersentinel.app.domain.security.resolveAction

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppScanScreen(
    viewModel: AppScanViewModel = hiltViewModel(),
    onNavigateBack: () -> Unit = {},
    onNavigateToAppDetail: (String) -> Unit = {}
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    
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
            // Scanning progress or summary
            AnimatedContent(
                targetState = uiState.isScanning,
                transitionSpec = {
                    fadeIn() + slideInVertically() togetherWith fadeOut() + slideOutVertically()
                },
                label = "scan_state"
            ) { isScanning ->
                if (isScanning) {
                    ScanningProgress(
                        progress = uiState.scanProgress,
                        currentApp = uiState.currentScanningApp
                    )
                } else if (uiState.summary != null) {
                    ScanSummaryCard(summary = uiState.summary!!)
                }
            }
            
            // Filter chips
            if (!uiState.isScanning && uiState.reports.isNotEmpty()) {
                FilterChipRow(
                    selectedFilter = uiState.filter,
                    onFilterChange = { viewModel.setFilter(it) },
                    summary = uiState.summary
                )
            }
            
            // Results list
            if (uiState.isScanning) {
                // Show placeholder during scan
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    CircularProgressIndicator()
                }
            } else if (uiState.reports.isEmpty()) {
                EmptyState(onStartScan = { viewModel.startScan() })
            } else {
                LazyColumn(
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    val filteredReports = when (uiState.filter) {
                        AppFilter.ALL -> uiState.reports
                        AppFilter.CRITICAL -> uiState.reports.filter { it.overallRisk == RiskLevel.CRITICAL }
                        AppFilter.HIGH_RISK -> uiState.reports.filter { it.overallRisk == RiskLevel.HIGH }
                        AppFilter.MEDIUM_RISK -> uiState.reports.filter { it.overallRisk == RiskLevel.MEDIUM }
                        AppFilter.SAFE -> uiState.reports.filter { 
                            it.overallRisk == RiskLevel.NONE || it.overallRisk == RiskLevel.LOW 
                        }
                        AppFilter.OVER_PRIVILEGED -> uiState.reports.filter { 
                            it.permissionAnalysis.isOverPrivileged 
                        }
                    }
                    
                    items(
                        items = filteredReports,
                        key = { it.app.packageName }
                    ) { report ->
                        AppReportCard(
                            report = report,
                            onClick = { onNavigateToAppDetail(report.app.packageName) }
                        )
                    }
                    
                    item {
                        Spacer(Modifier.height(80.dp))
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
            .padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        AppFilter.entries.forEach { filter ->
            val count = summary?.let {
                when (filter) {
                    AppFilter.ALL -> it.totalAppsScanned
                    AppFilter.CRITICAL -> it.criticalRiskApps
                    AppFilter.HIGH_RISK -> it.highRiskApps
                    AppFilter.MEDIUM_RISK -> it.mediumRiskApps
                    AppFilter.SAFE -> it.safeApps
                    AppFilter.OVER_PRIVILEGED -> it.overPrivilegedApps
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
    
    // Use human-readable risk labels
    val riskLabel = RiskLabels.getLabel(report.overallRisk)
    val riskColor = Color(riskLabel.color)
    
    // Use secure trust verification (packageName + SHA-256 cert)
    val isTrusted = report.trustVerification.isTrusted
    val developerName = report.trustVerification.developerName
    
    Card(
        onClick = { expanded = !expanded },
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            // Header row
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Risk indicator
                Box(
                    modifier = Modifier
                        .size(12.dp)
                        .clip(CircleShape)
                        .background(riskColor)
                )
                
                Spacer(Modifier.width(12.dp))
                
                // App info
                Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = report.app.appName,
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Medium,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f, fill = false)
                        )
                        if (isTrusted) {
                            Spacer(Modifier.width(6.dp))
                            Icon(
                                imageVector = Icons.Default.Verified,
                                contentDescription = developerName?.let { "Ověřeno: $it" } ?: "Ověřený vývojář",
                                tint = Color(0xFF2196F3),
                                modifier = Modifier.size(16.dp)
                            )
                        }
                    }
                    // Human-readable status instead of package name
                    Text(
                        text = riskLabel.shortDescription,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                
                // User-friendly risk badge
                Surface(
                    color = riskColor.copy(alpha = 0.1f),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(
                        text = riskLabel.badge,
                        style = MaterialTheme.typography.labelMedium,
                        color = riskColor,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                    )
                }
                
                Spacer(Modifier.width(8.dp))
                
                Icon(
                    imageVector = if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            
            // Quick summary - user friendly
            Spacer(Modifier.height(8.dp))
            
            // Show main concern in simple terms
            val mainConcern = when {
                report.signatureAnalysis.isDebugSigned -> 
                    "Může jít o neoficiální verzi aplikace"
                report.nativeLibAnalysis.hasSuspiciousLibs -> 
                    "Obsahuje neobvyklý kód"
                report.permissionAnalysis.isOverPrivileged -> 
                    "Má více oprávnění než potřebuje"
                report.issues.any { it.severity == RiskLevel.CRITICAL } ->
                    "Vyžaduje vaši pozornost"
                report.app.targetSdk < 29 ->
                    "Navržena pro starší Android"
                else -> null
            }
            
            mainConcern?.let { concern ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            riskColor.copy(alpha = 0.1f),
                            RoundedCornerShape(8.dp)
                        )
                        .padding(10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Default.Info,
                        contentDescription = null,
                        tint = riskColor,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = concern,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }
            
            // Expanded content
            AnimatedVisibility(visible = expanded) {
                Column(modifier = Modifier.padding(top = 12.dp)) {
                    HorizontalDivider()
                    Spacer(Modifier.height(12.dp))
                    
                    // Dangerous permissions - user friendly title
                    if (report.permissionAnalysis.dangerousPermissions.isNotEmpty()) {
                        Text(
                            text = "K čemu má aplikace přístup",
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.SemiBold
                        )
                        Spacer(Modifier.height(8.dp))
                        
                        report.permissionAnalysis.dangerousPermissions
                            .filter { it.isGranted }
                            .take(5)
                            .forEach { perm ->
                                PermissionRow(permission = perm)
                            }
                        
                        val hiddenCount = report.permissionAnalysis.dangerousPermissions
                            .count { it.isGranted } - 5
                        if (hiddenCount > 0) {
                            Text(
                                text = "... a $hiddenCount dalších",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(start = 32.dp, top = 4.dp)
                            )
                        }
                    }
                    
                    // Issues - user friendly title
                    if (report.issues.isNotEmpty()) {
                        Spacer(Modifier.height(12.dp))
                        Text(
                            text = "Co doporučujeme zkontrolovat",
                            style = MaterialTheme.typography.labelLarge,
                            fontWeight = FontWeight.SemiBold
                        )
                        Spacer(Modifier.height(8.dp))
                        
                        report.issues.take(3).forEach { issue ->
                            IssueRow(
                                issue = issue,
                                onActionClick = { 
                                    resolveAction(context, com.cybersentinel.app.domain.security.SecurityIssue(
                                        id = issue.id,
                                        title = issue.title,
                                        description = issue.description,
                                        impact = issue.impact,
                                        severity = when (issue.severity) {
                                            RiskLevel.CRITICAL -> com.cybersentinel.app.domain.security.SecurityIssue.Severity.CRITICAL
                                            RiskLevel.HIGH -> com.cybersentinel.app.domain.security.SecurityIssue.Severity.HIGH
                                            RiskLevel.MEDIUM -> com.cybersentinel.app.domain.security.SecurityIssue.Severity.MEDIUM
                                            RiskLevel.LOW -> com.cybersentinel.app.domain.security.SecurityIssue.Severity.LOW
                                            RiskLevel.NONE -> com.cybersentinel.app.domain.security.SecurityIssue.Severity.INFO
                                        },
                                        category = com.cybersentinel.app.domain.security.SecurityIssue.Category.APPS,
                                        action = issue.action
                                    ))
                                }
                            )
                        }
                    }
                    
                    // Signature info
                    Spacer(Modifier.height(12.dp))
                    Text(
                        text = "Podpis aplikace",
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.SemiBold
                    )
                    Spacer(Modifier.height(8.dp))
                    
                    Row(
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = if (report.signatureAnalysis.isDebugSigned) 
                                Icons.Default.Warning else Icons.Default.Verified,
                            contentDescription = null,
                            tint = if (report.signatureAnalysis.isDebugSigned) 
                                Color(0xFFFF9800) else Color(0xFF4CAF50),
                            modifier = Modifier.size(20.dp)
                        )
                        Spacer(Modifier.width(8.dp))
                        Column {
                            Text(
                                text = report.signatureAnalysis.signatureScheme,
                                style = MaterialTheme.typography.bodyMedium
                            )
                            Text(
                                text = if (report.signatureAnalysis.isDebugSigned) 
                                    "Debug certifikát - neoficiální build" 
                                else "Validní produkční podpis",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                    
                    // Technical details
                    Spacer(Modifier.height(12.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        TechDetail("Target SDK", "Android ${report.app.targetSdk}")
                        TechDetail("Nativní kód", if (report.nativeLibAnalysis.hasNativeCode) "Ano" else "Ne")
                        TechDetail("Velikost", formatSize(report.app.apkSizeBytes))
                    }
                }
            }
        }
    }
}

@Composable
private fun QuickStat(
    icon: ImageVector,
    value: String,
    label: String
) {
    Row(
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            modifier = Modifier.size(16.dp),
            tint = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(Modifier.width(4.dp))
        Text(
            text = value,
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.SemiBold
        )
        Spacer(Modifier.width(4.dp))
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun PermissionRow(permission: PermissionDetail) {
    val riskColor = Color(permission.riskLevel.color)
    
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = permission.category.icon,
            modifier = Modifier.width(24.dp)
        )
        Spacer(Modifier.width(8.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = permission.shortName,
                style = MaterialTheme.typography.bodyMedium
            )
            Text(
                text = permission.description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
        Surface(
            color = riskColor.copy(alpha = 0.1f),
            shape = RoundedCornerShape(4.dp)
        ) {
            Text(
                text = permission.riskLevel.label,
                style = MaterialTheme.typography.labelSmall,
                color = riskColor,
                modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
            )
        }
    }
}

@Composable
private fun IssueRow(
    issue: AppSecurityIssue,
    onActionClick: () -> Unit
) {
    val severityColor = Color(issue.severity.color)
    
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(8.dp)
                .clip(CircleShape)
                .background(severityColor)
        )
        Spacer(Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = issue.title,
                style = MaterialTheme.typography.bodyMedium
            )
            Text(
                text = issue.impact,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
        }
        TextButton(onClick = onActionClick) {
            Text("Opravit")
        }
    }
}

@Composable
private fun TechDetail(label: String, value: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.SemiBold
        )
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
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
    CRITICAL("Kritické"),
    HIGH_RISK("Vysoké"),
    MEDIUM_RISK("Střední"),
    SAFE("Bezpečné"),
    OVER_PRIVILEGED("Nadměrná oprávnění")
}
