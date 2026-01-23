package com.cybersentinel.ui.common

import android.Manifest
import android.os.Build
import android.widget.Toast
import androidx.activity.compose.ManagedActivityResultLauncher
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.platform.LocalContext

@Composable
fun RememberPermissionLauncher(onResult: (Boolean) -> Unit): ManagedActivityResultLauncher<String, Boolean> {
    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
        onResult
    )
    return launcher
}

@Composable
fun RequestCameraPermission(onGranted: () -> Unit) {
    val context = LocalContext.current
    val cameraLauncher = RememberPermissionLauncher { granted ->
        if (granted) {
            onGranted()
        } else {
            Toast.makeText(context, "Camera permission required for QR scanning", Toast.LENGTH_SHORT).show()
        }
    }

    LaunchedEffect(Unit) {
        cameraLauncher.launch(Manifest.permission.CAMERA)
    }
}

@Composable
fun RequestWifiPermissions(onGranted: () -> Unit) {
    val context = LocalContext.current
    
    val nearbyLauncher = RememberPermissionLauncher { granted ->
        if (granted) {
            onGranted()
        } else {
            Toast.makeText(context, "Wi-Fi permission denied", Toast.LENGTH_SHORT).show()
        }
    }
    
    val locationLauncher = RememberPermissionLauncher { granted ->
        if (granted) {
            onGranted()
        } else {
            Toast.makeText(context, "Location permission denied", Toast.LENGTH_SHORT).show()
        }
    }

    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= 33) {
            nearbyLauncher.launch(Manifest.permission.NEARBY_WIFI_DEVICES)
        } else {
            locationLauncher.launch(Manifest.permission.ACCESS_FINE_LOCATION)
        }
    }
}

@Composable  
fun RequestNotificationPermission(onResult: (Boolean) -> Unit) {
    val context = LocalContext.current
    val notificationLauncher = RememberPermissionLauncher { granted ->
        onResult(granted)
        if (!granted) {
            Toast.makeText(context, "Notification permission denied", Toast.LENGTH_SHORT).show()
        }
    }

    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= 33) {
            notificationLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            onResult(true) // Pre-13 doesn't need runtime permission
        }
    }
}