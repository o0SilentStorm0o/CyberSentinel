package com.cybersentinel.app.ui.screens.dashboard

import android.content.Intent
import android.net.Uri
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.*
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.cybersentinel.app.domain.security.ActionType
import com.cybersentinel.app.domain.security.IssueAction
import com.cybersentinel.app.domain.security.ScoreLevel
import com.cybersentinel.app.domain.security.SecurityIssue
import com.cybersentinel.app.domain.security.SecurityScore
import com.cybersentinel.app.domain.security.resolveAction

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DashboardScreen(
    viewModel: DashboardViewModel = hiltViewModel(),
    onNavigateToIssue: (SecurityIssue) -> Unit = {}
) {
    val ui by viewModel.ui.collectAsStateWithLifecycle()
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("CyberSentinel") },
                actions = {
                    IconButton(
                        onClick = { viewModel.runSecurityScan() },
                        enabled = !ui.isScanning
                    ) {
                        if (ui.isScanning) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(24.dp),
                                strokeWidth = 2.dp
                            )
                        } else {
                            Icon(Icons.Default.Refresh, contentDescription = "Skenovat")
                        }
                    }
                }
            )
        }
    ) { padding ->
        if (ui.isLoading) {
            Box(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator()
                    Spacer(Modifier.height(16.dp))
                    Text("Analyzuji zabezpečení...")
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Main Score Card
                item {
                    ui.securityScore?.let { score ->
                        SecurityScoreCard(score = score)
                    }
                }
                
                // Quick Actions
                item {
                    QuickActionsRow()
                }
                
                // Issues List
                ui.securityScore?.let { score ->
                    if (score.issues.isNotEmpty()) {
                        item {
                            Text(
                                text = "Nalezená rizika (${score.issues.size})",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold
                            )
                        }
                        
                        items(score.issues) { issue ->
                            IssueCard(
                                issue = issue,
                                onClick = { onNavigateToIssue(issue) }
                            )
                        }
                    } else {
                        item {
                            NoIssuesCard()
                        }
                    }
                }
                
                // Score Breakdown
                item {
                    ui.securityScore?.let { score ->
                        ScoreBreakdownCard(score = score)
                    }
                }
            }
        }
    }
}

@Composable
private fun SecurityScoreCard(score: SecurityScore) {
    val scoreColor = when (score.level) {
        ScoreLevel.EXCELLENT -> Color(0xFF4CAF50)
        ScoreLevel.GOOD -> Color(0xFF8BC34A)
        ScoreLevel.FAIR -> Color(0xFFFFEB3B)
        ScoreLevel.AT_RISK -> Color(0xFFFF9800)
        ScoreLevel.CRITICAL -> Color(0xFFF44336)
    }
    
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Animated Score Circle
            Box(
                modifier = Modifier.size(180.dp),
                contentAlignment = Alignment.Center
            ) {
                // Background circle
                Canvas(modifier = Modifier.fillMaxSize()) {
                    drawArc(
                        color = scoreColor.copy(alpha = 0.2f),
                        startAngle = -90f,
                        sweepAngle = 360f,
                        useCenter = false,
                        style = Stroke(width = 16.dp.toPx(), cap = StrokeCap.Round)
                    )
                }
                
                // Progress circle
                val animatedProgress by animateFloatAsState(
                    targetValue = score.score / 100f,
                    animationSpec = tween(1000, easing = FastOutSlowInEasing),
                    label = "score"
                )
                
                Canvas(modifier = Modifier.fillMaxSize()) {
                    drawArc(
                        color = scoreColor,
                        startAngle = -90f,
                        sweepAngle = animatedProgress * 360f,
                        useCenter = false,
                        style = Stroke(width = 16.dp.toPx(), cap = StrokeCap.Round)
                    )
                }
                
                // Score text
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text = "${score.score}",
                        fontSize = 48.sp,
                        fontWeight = FontWeight.Bold,
                        color = scoreColor
                    )
                    Text(
                        text = "/ 100",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            
            Spacer(Modifier.height(16.dp))
            
            // Level label
            Surface(
                color = scoreColor.copy(alpha = 0.15f),
                shape = RoundedCornerShape(20.dp)
            ) {
                Text(
                    text = "${score.level.emoji} ${score.level.label}",
                    modifier = Modifier.padding(horizontal = 20.dp, vertical = 8.dp),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    color = scoreColor
                )
            }
            
            Spacer(Modifier.height(8.dp))
            
            // Summary text
            val summaryText = when {
                score.issues.isEmpty() -> "Vaše zařízení je dobře zabezpečené"
                score.issues.size == 1 -> "Nalezeno 1 bezpečnostní riziko"
                score.issues.size < 5 -> "Nalezena ${score.issues.size} bezpečnostní rizika"
                else -> "Nalezeno ${score.issues.size} bezpečnostních rizik"
            }
            
            Text(
                text = summaryText,
                style = MaterialTheme.typography.bodyLarge,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun QuickActionsRow() {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        QuickActionButton(
            icon = Icons.Default.QrCodeScanner,
            label = "Skenovat QR",
            modifier = Modifier.weight(1f),
            onClick = { }
        )
        QuickActionButton(
            icon = Icons.Default.Wifi,
            label = "Wi-Fi check",
            modifier = Modifier.weight(1f),
            onClick = { }
        )
        QuickActionButton(
            icon = Icons.Default.Password,
            label = "Heslo",
            modifier = Modifier.weight(1f),
            onClick = { }
        )
    }
}

@Composable
private fun QuickActionButton(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    modifier: Modifier = Modifier,
    onClick: () -> Unit
) {
    OutlinedCard(
        onClick = onClick,
        modifier = modifier
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(
                imageVector = icon,
                contentDescription = label,
                modifier = Modifier.size(28.dp),
                tint = MaterialTheme.colorScheme.primary
            )
            Spacer(Modifier.height(4.dp))
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium
            )
        }
    }
}

@Composable
private fun IssueCard(
    issue: SecurityIssue,
    onClick: () -> Unit
) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var expanded by remember { mutableStateOf(false) }
    
    val severityColor = when (issue.severity) {
        SecurityIssue.Severity.CRITICAL -> Color(0xFFF44336)
        SecurityIssue.Severity.HIGH -> Color(0xFFFF9800)
        SecurityIssue.Severity.MEDIUM -> Color(0xFFFFEB3B)
        SecurityIssue.Severity.LOW -> Color(0xFF4CAF50)
        SecurityIssue.Severity.INFO -> Color(0xFF2196F3)
    }
    
    val categoryIcon = when (issue.category) {
        SecurityIssue.Category.DEVICE -> Icons.Default.PhoneAndroid
        SecurityIssue.Category.APPS -> Icons.Default.Apps
        SecurityIssue.Category.NETWORK -> Icons.Default.Wifi
        SecurityIssue.Category.ACCOUNTS -> Icons.Default.AccountCircle
        SecurityIssue.Category.PASSWORDS -> Icons.Default.Password
    }
    
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
                // Severity indicator
                Box(
                    modifier = Modifier
                        .size(10.dp)
                        .clip(CircleShape)
                        .background(severityColor)
                )
                
                Spacer(Modifier.width(12.dp))
                
                // Category icon
                Icon(
                    imageVector = categoryIcon,
                    contentDescription = null,
                    modifier = Modifier.size(24.dp),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
                
                Spacer(Modifier.width(12.dp))
                
                // Title and severity badge
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = issue.title,
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.Medium
                    )
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = issue.severity.label,
                            style = MaterialTheme.typography.labelSmall,
                            color = severityColor
                        )
                        if (issue.confidence != SecurityIssue.Confidence.HIGH) {
                            Text(
                                text = "• ${issue.confidence.label} jistota",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
                
                // Expand icon
                Icon(
                    imageVector = if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    contentDescription = if (expanded) "Sbalit" else "Rozbalit",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            
            // Expanded content
            if (expanded) {
                Spacer(Modifier.height(12.dp))
                
                // Description
                Text(
                    text = issue.description,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                
                Spacer(Modifier.height(8.dp))
                
                // Impact (why it matters)
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            severityColor.copy(alpha = 0.1f),
                            RoundedCornerShape(8.dp)
                        )
                        .padding(12.dp),
                    verticalAlignment = Alignment.Top
                ) {
                    Icon(
                        imageVector = Icons.Default.Warning,
                        contentDescription = null,
                        modifier = Modifier.size(18.dp),
                        tint = severityColor
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = issue.impact,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
                
                // Source and confidence
                issue.source?.let { source ->
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = "Zdroj: $source",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                
                // Action button
                if (issue.action !is IssueAction.None) {
                    Spacer(Modifier.height(12.dp))
                    
                    val actionLabel = when (val action = issue.action) {
                        is IssueAction.OpenSettings -> action.label
                        is IssueAction.OpenPlayStore -> action.label
                        is IssueAction.OpenUrl -> action.label
                        is IssueAction.InAppAction -> action.label
                        IssueAction.None -> ""
                    }
                    
                    Button(
                        onClick = {
                            when (val action = issue.action) {
                                is IssueAction.OpenSettings -> {
                                    try {
                                        context.startActivity(
                                            android.content.Intent(action.settingsAction).apply {
                                                flags = android.content.Intent.FLAG_ACTIVITY_NEW_TASK
                                            }
                                        )
                                    } catch (e: Exception) {
                                        // Fallback to main settings
                                        context.startActivity(
                                            android.content.Intent(android.provider.Settings.ACTION_SETTINGS).apply {
                                                flags = android.content.Intent.FLAG_ACTIVITY_NEW_TASK
                                            }
                                        )
                                    }
                                }
                                is IssueAction.OpenPlayStore -> {
                                    try {
                                        context.startActivity(
                                            android.content.Intent(
                                                android.content.Intent.ACTION_VIEW,
                                                android.net.Uri.parse("market://details?id=${action.packageName}")
                                            ).apply {
                                                flags = android.content.Intent.FLAG_ACTIVITY_NEW_TASK
                                            }
                                        )
                                    } catch (e: Exception) {
                                        // Fallback to web
                                        context.startActivity(
                                            android.content.Intent(
                                                android.content.Intent.ACTION_VIEW,
                                                android.net.Uri.parse("https://play.google.com/store/apps/details?id=${action.packageName}")
                                            )
                                        )
                                    }
                                }
                                is IssueAction.OpenUrl -> {
                                    context.startActivity(
                                        android.content.Intent(
                                            android.content.Intent.ACTION_VIEW,
                                            android.net.Uri.parse(action.url)
                                        )
                                    )
                                }
                                is IssueAction.InAppAction -> {
                                    onClick()
                                }
                                IssueAction.None -> {}
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(
                            imageVector = Icons.Default.OpenInNew,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(actionLabel)
                    }
                }
            }
        }
    }
}

@Composable
private fun NoIssuesCard() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF4CAF50).copy(alpha = 0.1f)
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(20.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Default.CheckCircle,
                contentDescription = null,
                tint = Color(0xFF4CAF50),
                modifier = Modifier.size(32.dp)
            )
            Spacer(Modifier.width(16.dp))
            Column {
                Text(
                    text = "Žádná rizika nenalezena",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    text = "Vaše zařízení je aktuálně dobře zabezpečené",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun ScoreBreakdownCard(score: SecurityScore) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = "Rozpad skóre",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            
            BreakdownRow("Zařízení", score.breakdown.device, 25)
            BreakdownRow("Aplikace", score.breakdown.apps, 25)
            BreakdownRow("Síť", score.breakdown.network, 25)
            BreakdownRow("Účty", score.breakdown.accounts, 25)
        }
    }
}

@Composable
private fun BreakdownRow(label: String, value: Int, max: Int) {
    val progress = value.toFloat() / max
    val color = when {
        progress >= 0.8f -> Color(0xFF4CAF50)
        progress >= 0.5f -> Color(0xFFFFEB3B)
        else -> Color(0xFFF44336)
    }
    
    Column {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(text = label, style = MaterialTheme.typography.bodyMedium)
            Text(
                text = "$value / $max",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Spacer(Modifier.height(4.dp))
        LinearProgressIndicator(
            progress = { progress },
            modifier = Modifier
                .fillMaxWidth()
                .height(6.dp)
                .clip(RoundedCornerShape(3.dp)),
            color = color,
            trackColor = color.copy(alpha = 0.2f)
        )
    }
}
