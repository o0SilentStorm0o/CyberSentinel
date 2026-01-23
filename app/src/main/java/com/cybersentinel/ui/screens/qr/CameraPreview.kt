package com.cybersentinel.ui.screens.qr

import android.Manifest
import android.util.Log
import androidx.camera.core.*
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.accompanist.permissions.ExperimentalPermissionsApi
import com.google.accompanist.permissions.PermissionState
import com.google.accompanist.permissions.isGranted
import com.google.accompanist.permissions.rememberPermissionState
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import java.util.concurrent.Executors
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

/**
 * Camera Preview pro QR/Barcode scanning s ML Kit
 */
@OptIn(ExperimentalPermissionsApi::class)
@Composable
fun CameraPreview(
    onQrCodeDetected: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val cameraPermissionState: PermissionState = rememberPermissionState(Manifest.permission.CAMERA)
    
    if (cameraPermissionState.status.isGranted) {
        AndroidView(
            factory = { ctx ->
                val previewView = PreviewView(ctx)
                val executor = ContextCompat.getMainExecutor(ctx)
                val cameraProviderFuture = ProcessCameraProvider.getInstance(ctx)
                
                cameraProviderFuture.addListener({
                    try {
                        val cameraProvider = cameraProviderFuture.get()
                        bindPreview(
                            cameraProvider = cameraProvider,
                            previewView = previewView,
                            lifecycleOwner = lifecycleOwner,
                            onQrCodeDetected = onQrCodeDetected
                        )
                    } catch (e: Exception) {
                        Log.e("CameraPreview", "Camera setup failed", e)
                    }
                }, executor)
                
                previewView
            },
            modifier = modifier
                .fillMaxSize()
                .clip(RoundedCornerShape(16.dp))
        )
    } else {
        // Permission request UI
        Column(
            modifier = modifier.fillMaxSize(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = "Pro skenování QR kódů je potřeba oprávnění k použití kamery",
                style = MaterialTheme.typography.bodyLarge
            )
            
            Spacer(modifier = Modifier.height(16.dp))
            
            Button(
                onClick = { cameraPermissionState.launchPermissionRequest() }
            ) {
                Text("Povolit kameru")
            }
        }
    }
}

/**
 * Připojí camera preview a QR scanner
 */
private fun bindPreview(
    cameraProvider: ProcessCameraProvider,
    previewView: PreviewView,
    lifecycleOwner: androidx.lifecycle.LifecycleOwner,
    onQrCodeDetected: (String) -> Unit
) {
    val preview = Preview.Builder().build()
    preview.setSurfaceProvider(previewView.surfaceProvider)
    
    val imageCapture = ImageCapture.Builder().build()
    
    val imageAnalyzer = ImageAnalysis.Builder()
        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
        .build()
    
    val barcodeScanner = BarcodeScanning.getClient()
    
    imageAnalyzer.setAnalyzer(Executors.newSingleThreadExecutor()) { imageProxy ->
        val rotationDegrees = imageProxy.imageInfo.rotationDegrees
        val image = imageProxy.image
        
        if (image != null) {
            val inputImage = InputImage.fromMediaImage(image, rotationDegrees)
            
            barcodeScanner.process(inputImage)
                .addOnSuccessListener { barcodes ->
                    for (barcode in barcodes) {
                        when (barcode.valueType) {
                            Barcode.TYPE_URL -> {
                                barcode.url?.url?.let { url ->
                                    onQrCodeDetected(url)
                                }
                            }
                            Barcode.TYPE_TEXT -> {
                                barcode.displayValue?.let { text ->
                                    onQrCodeDetected(text)
                                }
                            }
                        }
                    }
                }
                .addOnFailureListener { exception ->
                    Log.e("BarcodeScanner", "Barcode scanning failed", exception)
                }
                .addOnCompleteListener {
                    imageProxy.close()
                }
        } else {
            imageProxy.close()
        }
    }
    
    val cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA
    
    try {
        cameraProvider.unbindAll()
        cameraProvider.bindToLifecycle(
            lifecycleOwner,
            cameraSelector,
            preview,
            imageCapture,
            imageAnalyzer
        )
    } catch (e: Exception) {
        Log.e("CameraPreview", "Camera binding failed", e)
    }
}