package com.cybersentinel.app.ui.theme


import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable


private val Dark = darkColorScheme()


@Composable
fun CSTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = Dark, content = content)
}