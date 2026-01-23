package com.cybersentinel.ui.screens.password

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/**
 * HIBP Password Check screen s ViewModel a live strength meter
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PasswordCheckScreen(
    viewModel: PasswordCheckViewModel = hiltViewModel()
) {
    val ui by viewModel.ui.collectAsStateWithLifecycle()
    val displayLevel = viewModel.deriveDisplayLevel()
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("HIBP Password Check") }
            )
        },
        // Důležité: aby Scaffold nepřidával vlastní insets navíc
        contentWindowInsets = WindowInsets(0)
    ) { paddingValues ->
        // LazyColumn = jistota scrollu i na menších displejích
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                // Přeneseme padding ze Scaffoldu a zároveň ho „spotřebujeme",
                // aby se nepočítal dvakrát.
                .padding(paddingValues)
                .consumeWindowInsets(paddingValues)
                // Ať se obsah neposouvá pod klávesnici ani systémovou lištu
                .imePadding()
                .navigationBarsPadding(),
            contentPadding = PaddingValues(
                start = 16.dp, end = 16.dp, top = 16.dp, bottom = 24.dp
            ),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item { InfoCard() }

            item {
                PasswordInput(
                    value = ui.password,
                    onValueChange = viewModel::onPasswordChange,
                    isVisible = ui.isVisible,
                    onToggleVisibility = viewModel::onToggleVisibility,
                    onClear = viewModel::clearPassword,
                    enabled = !ui.isChecking,
                    onDone = viewModel::onCheck
                )
            }

            // Live meter (bez sítě)
            ui.liveStrength?.let { strength ->
                item {
                    LiveStrengthMeter(
                        level = displayLevel,
                        entropyBits = strength.entropyBits
                    )
                }
            }

            item {
                CheckButton(
                    isChecking = ui.isChecking,
                    enabled = ui.password.isNotBlank() && !ui.isChecking,
                    onClick = viewModel::onCheck
                )
            }

            when (val r = ui.result) {
                is HibpResult.Ok -> item { 
                    ResultCard(
                        result = r,
                        displayLevel = displayLevel
                    ) 
                }
                is HibpResult.Error -> item { 
                    ErrorCard(
                        message = r.message,
                        retryCount = ui.retryCount,
                        onRetry = viewModel::onRetry,
                        canRetry = !ui.isChecking
                    ) 
                }
                else -> {}
            }

            item { PrivacyInfoCard() }
        }
    }
}

/**
 * Password input field s clipboard a visibility controls
 */
@Composable
private fun PasswordInput(
    value: String,
    onValueChange: (String) -> Unit,
    isVisible: Boolean,
    onToggleVisibility: () -> Unit,
    onClear: () -> Unit,
    enabled: Boolean,
    onDone: () -> Unit
) {
    // Clipboard support
    val clipboardManager = LocalClipboardManager.current
    val keyboardController = LocalSoftwareKeyboardController.current
    
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text("Heslo ke kontrole") },
        placeholder = { Text("Zadejte heslo…") },
        singleLine = true,
        keyboardOptions = KeyboardOptions(
            keyboardType = KeyboardType.Password,
            imeAction = ImeAction.Done
        ),
        keyboardActions = KeyboardActions(
            onDone = { 
                keyboardController?.hide()
                onDone() 
            }
        ),
        visualTransformation = if (isVisible) VisualTransformation.None else PasswordVisualTransformation(),
        trailingIcon = {
            Row {
                // Paste button with auto-clear
                IconButton(onClick = {
                    clipboardManager.getText()?.text?.let { text ->
                        onValueChange(text)
                        // Clear clipboard after paste for security
                        clipboardManager.setText(androidx.compose.ui.text.AnnotatedString(""))
                    }
                }) {
                    Icon(Icons.Default.ContentPaste, "Vložit a vymazat schránku")
                }
                
                // Clear button
                if (value.isNotBlank() && enabled) {
                    IconButton(onClick = onClear) {
                        Icon(Icons.Default.Clear, "Vymazat")
                    }
                }
                
                // Visibility toggle
                IconButton(onClick = onToggleVisibility) {
                    Icon(
                        imageVector = if (isVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                        contentDescription = if (isVisible) "Skrýt heslo" else "Zobrazit heslo"
                    )
                }
            }
        },
        modifier = Modifier.fillMaxWidth(),
        enabled = enabled
    )
}

/**
 * Live strength meter s progress barem
 */
@Composable
private fun LiveStrengthMeter(level: StrengthLevel, entropyBits: Double) {
    val (label, color) = when (level) {
        StrengthLevel.VERY_WEAK -> "Velmi slabé" to Color(0xFFF44336)
        StrengthLevel.WEAK -> "Slabé" to Color(0xFFFF5722)
        StrengthLevel.MEDIUM -> "Střední" to Color(0xFFFFC107)
        StrengthLevel.STRONG -> "Silné" to Color(0xFF4CAF50)
        StrengthLevel.VERY_STRONG -> "Velmi silné" to Color(0xFF2E7D32)
    }
    
    val pct = (entropyBits.coerceIn(0.0, 100.0) / 100.0).toFloat()
    
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = color.copy(alpha = 0.1f))
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
                    text = "Síla hesla (předběžně)",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
                
                Text(
                    text = label,
                    style = MaterialTheme.typography.bodyMedium,
                    color = color,
                    fontWeight = FontWeight.Bold
                )
            }
            
            Spacer(modifier = Modifier.height(8.dp))
            
            LinearProgressIndicator(
                progress = { pct },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(6.dp),
                trackColor = MaterialTheme.colorScheme.surfaceVariant,
                color = color
            )
            
            Spacer(modifier = Modifier.height(8.dp))
            
            Text(
                text = "Entropie: ${entropyBits.toInt()} bitů",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

/**
 * Check button s loading indikátorem
 */
@Composable
private fun CheckButton(isChecking: Boolean, enabled: Boolean, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
        enabled = enabled
    ) {
        if (isChecking) {
            CircularProgressIndicator(
                modifier = Modifier.size(20.dp),
                strokeWidth = 2.dp,
                color = MaterialTheme.colorScheme.onPrimary
            )
            Spacer(Modifier.width(8.dp))
            Text("Kontroluji proti HIBP…")
        } else {
            Icon(Icons.Default.Security, contentDescription = null, modifier = Modifier.size(20.dp))
            Spacer(Modifier.width(8.dp))
            Text("Zkontrolovat heslo")
        }
    }
}

/**
 * Info header card
 */
@Composable
private fun InfoCard() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = Icons.Default.Shield,
                    contentDescription = null,
                    modifier = Modifier.size(24.dp),
                    tint = MaterialTheme.colorScheme.onPrimaryContainer
                )
                
                Spacer(modifier = Modifier.width(8.dp))
                
                Text(
                    text = "Have I Been Pwned Check",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onPrimaryContainer
                )
            }
            
            Spacer(modifier = Modifier.height(8.dp))
            
            Text(
                text = "Bezpečně zkontrolujte, zda vaše heslo bylo kompromitováno v známých únicích dat. Používáme k-anonymity protokol - vaše heslo neopouští zařízení.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onPrimaryContainer,
                textAlign = TextAlign.Start
            )
        }
    }
}

/**
 * Result card for successful check s display level mapováním
 */
@Composable
private fun ResultCard(
    result: HibpResult.Ok,
    displayLevel: StrengthLevel
) {
    val strengthColor = when (displayLevel) {
        StrengthLevel.VERY_WEAK -> Color(0xFFF44336)
        StrengthLevel.WEAK -> Color(0xFFFF5722)
        StrengthLevel.MEDIUM -> Color(0xFFFF9800)
        StrengthLevel.STRONG -> Color(0xFF4CAF50)
        StrengthLevel.VERY_STRONG -> Color(0xFF2E7D32)
    }
    
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (result.compromised) 
                MaterialTheme.colorScheme.errorContainer 
            else MaterialTheme.colorScheme.surfaceVariant
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = if (result.compromised) Icons.Default.Warning else Icons.Default.CheckCircle,
                    contentDescription = null,
                    modifier = Modifier.size(24.dp),
                    tint = if (result.compromised) 
                        MaterialTheme.colorScheme.onErrorContainer 
                    else Color(0xFF4CAF50)
                )
                
                Spacer(modifier = Modifier.width(8.dp))
                
                Text(
                    text = if (result.compromised) "Heslo kompromitováno!" else "Heslo bezpečné",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = if (result.compromised) 
                        MaterialTheme.colorScheme.onErrorContainer 
                    else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            
            Spacer(modifier = Modifier.height(12.dp))
            
            if (result.compromised) {
                Text(
                    text = "Toto heslo bylo nalezeno v ${result.breachCount} úniku(ech) dat. Doporučujeme jej okamžitě změnit!",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onErrorContainer
                )
                
                Spacer(modifier = Modifier.height(8.dp))
            } else {
                Text(
                    text = "Toto heslo nebylo nalezeno v známých únicích dat.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                
                Spacer(modifier = Modifier.height(8.dp))
            }
            
            // Strength badge s display level mapováním
            StrengthBadge(
                level = displayLevel,
                entropy = result.strength.entropyBits,
                isCompromised = result.compromised
            )
        }
    }
}

/**
 * Strength badge s barevným označením
 */
@Composable
private fun StrengthBadge(
    level: StrengthLevel,
    entropy: Double,
    isCompromised: Boolean
) {
    val color = if (isCompromised) {
        // Kompromitované heslo nikdy nebude "zelené"
        when {
            entropy > 50 -> Color(0xFFFF5722) // Orange místo zelené
            else -> Color(0xFFF44336) // Red
        }
    } else {
        when (level) {
            StrengthLevel.VERY_WEAK -> Color(0xFFF44336)
            StrengthLevel.WEAK -> Color(0xFFFF5722)
            StrengthLevel.MEDIUM -> Color(0xFFFF9800)
            StrengthLevel.STRONG -> Color(0xFF4CAF50)
            StrengthLevel.VERY_STRONG -> Color(0xFF2E7D32)
        }
    }
    
    Surface(
        color = color,
        shape = MaterialTheme.shapes.small,
        modifier = Modifier.padding(vertical = 4.dp)
    ) {
        Text(
            text = "${level.name.replace("_", " ")} (${entropy.toInt()} bitů)",
            style = MaterialTheme.typography.labelMedium,
            color = Color.White,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
        )
    }
}

/**
 * Error card for failed checks s retry logikou
 */
@Composable
private fun ErrorCard(
    message: String,
    retryCount: Int,
    onRetry: () -> Unit,
    canRetry: Boolean
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = Icons.Default.Error,
                    contentDescription = null,
                    modifier = Modifier.size(24.dp),
                    tint = MaterialTheme.colorScheme.onErrorContainer
                )
                
                Spacer(modifier = Modifier.width(8.dp))
                
                Text(
                    text = "Chyba kontroly",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onErrorContainer
                )
            }
            
            Spacer(modifier = Modifier.height(8.dp))
            
            Text(
                text = message,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onErrorContainer
            )
            
            if (retryCount > 0) {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Pokus: $retryCount",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onErrorContainer.copy(alpha = 0.7f)
                )
            }
            
            Spacer(modifier = Modifier.height(12.dp))
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.End
            ) {
                OutlinedButton(
                    onClick = onRetry,
                    enabled = canRetry,
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = MaterialTheme.colorScheme.onErrorContainer
                    )
                ) {
                    Icon(
                        imageVector = Icons.Default.Refresh,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(4.dp))
                    Text("Zkusit znovu")
                }
            }
        }
    }
}

/**
 * Privacy info card
 */
@Composable
private fun PrivacyInfoCard() {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.secondaryContainer
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = Icons.Default.PrivacyTip,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp),
                    tint = MaterialTheme.colorScheme.onSecondaryContainer
                )
                
                Spacer(modifier = Modifier.width(8.dp))
                
                Text(
                    text = "Soukromí a bezpečnost",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSecondaryContainer
                )
            }
            
            Spacer(modifier = Modifier.height(8.dp))
            
            Text(
                text = "• Vaše heslo se nikdy neodesílá celé\n" +
                        "• Odesíláme pouze prvních 5 znaků SHA-1 hash\n" +
                        "• Používáme k-anonymity protokol pro soukromí\n" +
                        "• Heslo je automaticky vymazáno z paměti",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSecondaryContainer
            )
        }
    }
}