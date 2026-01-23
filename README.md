# CyberSentinel

Android security app for monitoring vulnerabilities and protecting users from common threats.

## Features

- **CVE Monitor** - Real-time feed of Android-related vulnerabilities from NVD and CIRCL APIs with relevance scoring
- **PhishGuard** - QR code scanner with phishing URL detection (IDN/punycode, suspicious TLDs, URL shorteners)
- **Wi-Fi Auditor** - Scans nearby networks and analyzes their security (WPA3/WPA2/WEP/Open)
- **Password Check** - HIBP integration using k-anonymity to check if passwords have been compromised
- **Background Alerts** - WorkManager-based notifications for critical CVEs

## Tech Stack

- Kotlin, Jetpack Compose, Material 3
- MVVM architecture with Hilt DI
- Room database, DataStore preferences
- Retrofit + Moshi for networking
- CameraX + ML Kit for barcode scanning
- WorkManager for background tasks

## Requirements

- Android Studio Giraffe or newer
- Min SDK 26 (Android 8.0)
- Target SDK 35

## Build

```bash
./gradlew assembleDebug
```

## License

MIT