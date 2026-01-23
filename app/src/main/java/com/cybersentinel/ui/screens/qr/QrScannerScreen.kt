package com.cybersentinel.ui.screens.qr

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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp

/**
 * PhishGuard QR Scanner screen s real-time scanning a URL analýzou
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QrScannerScreen() {
    var scannerActive by remember { mutableStateOf(false) }
    var analysisResult by remember { mutableStateOf<PhishingAnalysisResult?>(null) }
    val analyzer = remember { PhishGuardAnalyzer() }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("PhishGuard QR Scanner") },
                actions = {
                    IconButton(
                        onClick = { 
                            scannerActive = !scannerActive
                            if (!scannerActive) analysisResult = null
                        }
                    ) {
                        Icon(
                            imageVector = if (scannerActive) Icons.Default.Stop else Icons.Default.QrCodeScanner,
                            contentDescription = if (scannerActive) "Zastavit scanner" else "Spustit scanner"
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
            // Camera Preview nebo Instructions
            if (scannerActive) {
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(300.dp),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    CameraPreview(
                        onQrCodeDetected = { qrContent ->
                            // Analyze detected QR/URL
                            analysisResult = analyzer.analyzeUrl(qrContent)
                        },
                        modifier = Modifier.fillMaxSize()
                    )
                }
            } else {
                // Instructions card
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.primaryContainer
                    )
                ) {
                    Column(
                        modifier = Modifier.padding(24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Icon(
                            imageVector = Icons.Default.QrCodeScanner,
                            contentDescription = null,
                            modifier = Modifier.size(64.dp),
                            tint = MaterialTheme.colorScheme.onPrimaryContainer
                        )
                        
                        Spacer(modifier = Modifier.height(16.dp))
                        
                        Text(
                            text = "PhishGuard Scanner",
                            style = MaterialTheme.typography.headlineSmall,
                            color = MaterialTheme.colorScheme.onPrimaryContainer
                        )
                        
                        Spacer(modifier = Modifier.height(8.dp))
                        
                        Text(
                            text = "Skenuje QR kódy a analyzuje URLs na phishing hrozby",
                            style = MaterialTheme.typography.bodyMedium,
                            textAlign = TextAlign.Center,
                            color = MaterialTheme.colorScheme.onPrimaryContainer
                        )
                    }
                }
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            // Analysis Results
            analysisResult?.let { result ->
                AnalysisResultCard(result = result)
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            // Features info when not scanning
            if (!scannerActive) {
                FeaturesInfoCard()
            }
        }
    }
}

/**
 * Zobrazuje výsledky analýzy URL
 */
@Composable
private fun AnalysisResultCard(result: PhishingAnalysisResult) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = when (result.riskLevel) {
                RiskLevel.SAFE -> MaterialTheme.colorScheme.surfaceVariant
                RiskLevel.LOW -> Color(0xFFFFF3E0) // Light orange
                RiskLevel.MEDIUM -> Color(0xFFFFE0B2) // Orange
                RiskLevel.HIGH -> Color(0xFFFFCDD2) // Light red
            }
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
                Text(
                    text = "Analýza URL",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                
                RiskBadge(riskLevel = result.riskLevel, score = result.riskScore)
            }
            
            Spacer(modifier = Modifier.height(12.dp))
            
            // Original URL
            Text(
                text = "URL: ${result.originalUrl}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            
            // IDN info
            if (result.isIDN && result.decodedHost != null) {
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Default.Warning,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp),
                        tint = MaterialTheme.colorScheme.error
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text(
                        text = "IDN: ${result.decodedHost}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
            
            // Warnings
            if (result.warnings.isNotEmpty()) {
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = "Varování:",
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold
                )
                
                LazyColumn(
                    modifier = Modifier.heightIn(max = 200.dp)
                ) {
                    items(result.warnings) { warning ->
                        Row(
                            modifier = Modifier.padding(vertical = 2.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                imageVector = Icons.Default.Warning,
                                contentDescription = null,
                                modifier = Modifier.size(12.dp),
                                tint = MaterialTheme.colorScheme.error
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                text = warning,
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }
                }
            }
        }
    }
}

/**
 * Risk level badge
 */
@Composable
private fun RiskBadge(riskLevel: RiskLevel, score: Int) {
    val (backgroundColor, contentColor) = when (riskLevel) {
        RiskLevel.SAFE -> MaterialTheme.colorScheme.primary to MaterialTheme.colorScheme.onPrimary
        RiskLevel.LOW -> Color(0xFFFF9800) to Color.White
        RiskLevel.MEDIUM -> Color(0xFFFF5722) to Color.White
        RiskLevel.HIGH -> MaterialTheme.colorScheme.error to MaterialTheme.colorScheme.onError
    }
    
    Surface(
        shape = RoundedCornerShape(12.dp),
        color = backgroundColor
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = riskLevel.displayName,
                style = MaterialTheme.typography.labelSmall,
                color = contentColor,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.width(4.dp))
            Text(
                text = "($score%)",
                style = MaterialTheme.typography.labelSmall,
                color = contentColor
            )
        }
    }
}

/**
 * Informace o funkcích PhishGuard
 */
@Composable
private fun FeaturesInfoCard() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Text(
                text = "PhishGuard funkce:",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSecondaryContainer
            )
            
            Spacer(modifier = Modifier.height(12.dp))
            
            val features = listOf(
                "Real-time QR/Barcode scanning",
                "IDN/Punycode detekce",
                "URL shortener identifikace", 
                "Suspicious TLD kontrola",
                "Phishing keyword analýza",
                "Risk scoring algoritmus"
            )
            
            features.forEach { feature ->
                Row(
                    modifier = Modifier.padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Default.CheckCircle,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp),
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = feature,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSecondaryContainer
                    )
                }
            }
        }
    }
}