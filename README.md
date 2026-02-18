# CyberSentinel

**Security for everyone** — an Android security app that combines deterministic threat detection with evidence-based analysis. CyberSentinel scans installed apps, monitors device configuration, detects behavioral anomalies, and explains findings in clear, actionable language.

## Features

### Core Security Tools
- **CVE Monitor** — Real-time feed of Android-related vulnerabilities from NVD and CIRCL APIs with device-specific relevance scoring
- **PhishGuard** — QR code scanner with phishing URL detection (IDN/punycode, suspicious TLDs, URL shorteners)
- **Wi-Fi Auditor** — Scans nearby networks and analyzes their security (WPA3/WPA2/WEP/Open)
- **Password Check** — HIBP integration using k-anonymity to check if passwords have been compromised
- **Background Alerts** — WorkManager-based notifications for critical CVEs

### App Security Scanner (3-Axis Evidence Model)
The scanner evaluates every installed app across three independent axes:

| Axis | Engine | What it answers |
|------|--------|----------------|
| **Identity / Provenance** | `TrustEvidenceEngine` | Who made this app? Where did it come from? Can we verify the certificate? |
| **Capabilities** | `TrustRiskModel` | What dangerous permissions and special access does it have? Are they expected for its category? |
| **Change / Anomaly** | `BaselineManager` | Did anything change since last scan? Cert rotation, version rollback, installer switch, new permissions? |

**Key design principles:**
- **4-state verdicts:** CRITICAL → NEEDS_ATTENTION → INFO → SAFE (no scareware)
- **Combo gating:** A single permission is never enough for alarm — requires trust + capability + change correlation
- **Category awareness:** SMS permission on a messaging app ≠ SMS permission on a flashlight app
- **HARD vs SOFT findings:** Debug certificates and cert mismatches are always critical; sideloading with cert match is informational

### Special Access Inspector
Checks the **real enabled state** of dangerous special access services — not just manifest declarations:
- Accessibility services, Notification listeners, Device admin
- Default SMS/Dialer/Browser, Overlay permission, Battery optimization exemption
- Clusters are only "active" when the service is actually enabled by the user

### Config Baseline Engine
Monitors "hidden places" that attackers change silently:
- User CA certificates (MITM detection)
- Private DNS configuration
- VPN state and provider
- Wi-Fi proxy settings
- Enabled accessibility/notification services
- Default app changes, Developer options, USB debugging

### App Baseline Engine (Change Detection Axis)
Persists per-app state (cert, version, installer, permissions, exported surface) across scans:
- **First scan** creates the baseline — no change-based anomalies possible yet
- **Subsequent scans** detect drift: cert rotation, version rollback, installer switch, new high-risk permissions
- First-scan security gap is covered by identity axis (cert whitelist, signer domain) and capability axis (partition anomaly, privilege analysis)
- Anomalies are mapped through `AppSecurityScanner.mapBaselineAnomalyToFinding()` to the 3-axis model
- HARD anomalies (cert change, version rollback, new system app) → always CRITICAL, never suppressed
- SOFT anomalies (version update, permission set change) → suppressed for system apps (hygiene rules)
- INSTALLER_ANOMALY: HARD but at MEDIUM severity — does not alone trigger CRITICAL (benign migrations exist); escalates only through combination rules (R4b)

> **Source of truth:** see KDoc on `BaselineManager.compareWithBaseline()` for full initialization semantics and first-scan coverage model.

### Incident Pipeline
Standardized 3-level evidence model:
```
SecuritySignal (atomic observation) → SecurityEvent (time-bounded group) → SecurityIncident (with ranked hypotheses)
```
- **RootCauseResolver** — Generates and ranks hypotheses explaining WHY something happened (stalkerware, supply-chain attack, config tampering, legitimate update, etc.)
- Every hypothesis carries confidence score, supporting/contradicting evidence, and MITRE ATT&CK technique references
- Recommended actions are graduated: monitor → revoke access → uninstall → factory reset

### Sleeping Sentinel (Contracts — Implementation Planned)
Background behavioral monitor that will:
1. Periodically sample device state (battery, network, CPU, wakeups)
2. Build per-app behavioral baselines
3. Detect anomalies (battery drain while idle, network bursts at night, excessive wakeups, unusual context)
4. Correlate with App Scanner knowledge for context-aware analysis

Currently defined as interface contracts (`SentinelAnalyzer`, `SentinelBaselineManager`) with full data models. Implementation follows in Sprint 4.

### App Feature Vector
Structured knowledge base output transforming the scanner from "result producer" into a queryable knowledge source:
- 5 feature groups: Identity, Change, Capability, Surface, SpecialAccess
- Query helpers: `isHighPriorityTarget`, `hasSuspiciousProfile`, `shouldMonitor`
- Used by RootCauseResolver and future Sleeping Sentinel for context-aware decisions

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    App Security Scanner                      │
│  ┌─────────────┐ ┌──────────────┐ ┌───────────────────────┐ │
│  │TrustEvidence │ │ TrustRisk    │ │ Baseline              │ │
│  │Engine        │ │ Model        │ │ Manager               │ │
│  │(identity)    │ │(capabilities)│ │(change detection)     │ │
│  └──────┬───────┘ └──────┬───────┘ └───────────┬───────────┘ │
│         │                │                      │             │
│  ┌──────┴───────┐ ┌──────┴───────┐ ┌───────────┴───────────┐ │
│  │AppCategory   │ │SpecialAccess │ │ScanDiagnostics        │ │
│  │Detector      │ │Inspector     │ │(telemetry)            │ │
│  └──────────────┘ └──────────────┘ └───────────────────────┘ │
│                         │                                    │
│                    AppFeatureVector (knowledge base output)   │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────┴───────────────────────────────────┐
│                  Config Baseline Engine                       │
│        (CA certs, DNS, VPN, proxy, default apps)             │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────┴───────────────────────────────────┐
│                    Incident Pipeline                         │
│   SecuritySignal → SecurityEvent → SecurityIncident          │
│                         │                                    │
│                  RootCauseResolver                            │
│            (ranked hypotheses + actions)                      │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────┴───────────────────────────────────┐
│              Sleeping Sentinel (planned)                      │
│   SentinelWorker → SentinelAnalyzer → BehaviorAnomaly        │
│               ↕ queries AppFeatureVector                     │
└──────────────────────────────────────────────────────────────┘
```

## Tech Stack

- **Language:** Kotlin 2.0, Java 17
- **UI:** Jetpack Compose + Material 3 (dark theme)
- **DI:** Hilt 2.52
- **Database:** Room 2.6.1 (currently schema v5)
- **Networking:** Retrofit + Moshi
- **Camera:** CameraX + ML Kit (barcode scanning)
- **Background:** WorkManager
- **Testing:** JUnit 4 (903 tests, 0 failures)

## Project Structure

```
app/src/main/java/com/cybersentinel/app/
├── data/local/
│   ├── AppBaselineEntity.kt      # Baseline storage (Room, schema v5)
│   ├── AppDatabase.kt            # Room DB with migrations
│   ├── ConfigBaselineEntity.kt   # Config snapshot persistence
│   └── SecurityEventEntity.kt    # Security event persistence
├── di/
│   └── DatabaseModule.kt         # Hilt DI for DB + DAOs
├── domain/security/
│   ├── AppSecurityScanner.kt     # Main scanner orchestrator
│   ├── TrustEvidenceEngine.kt    # Identity/provenance axis
│   ├── TrustRiskModel.kt         # Capability/risk axis + verdict
│   ├── BaselineManager.kt        # Change detection axis
│   ├── AppCategoryDetector.kt    # App category classification
│   ├── SpecialAccessInspector.kt # Real enabled state checker
│   ├── AppFeatureVector.kt       # Structured knowledge output
│   ├── ConfigBaselineEngine.kt   # Device config monitoring
│   ├── SecurityIncidentModels.kt # 3-level incident pipeline
│   ├── RootCauseResolver.kt      # Hypothesis ranking engine
│   ├── ScanDiagnostics.kt        # Scan telemetry/diagnostics
│   └── TrustedAppsAndMessages.kt # Known-good cert DB + messages
├── domain/sentinel/
│   └── SleepingSentinelContract.kt # Behavioral monitor interfaces
└── ui/screens/
    └── appscan/AppScanScreen.kt  # Scanner UI (Compose)
```

## Testing

```bash
./gradlew testDebugUnitTest
```

**903 tests** across 10+ test classes covering:
- TrustRiskModel (91 tests) — verdict logic, combo gating, trust tiers, category whitelist
- AppCategoryDetector (29 tests) — category classification accuracy
- BaselineManager (18 tests) — change detection, anomaly types
- SecurityIncident (17 tests) — incident pipeline, hypothesis ranking
- AppFeatureVector (15 tests) — query helpers, knowledge base output
- SleepingSentinelContract (13 tests) — behavioral monitor data models
- TrustRiskModelSpecialAccess (11 tests) — cluster gating by real enabled state
- SpecialAccessInspector (10 tests) — snapshot data model, access counting
- ConfigBaselineEngine (8 tests) — delta detection, config hashing

## Requirements

- Android Studio Giraffe or newer
- Min SDK 26 (Android 8.0)
- Target SDK 35
- Compile SDK 35

## Build

```bash
./gradlew assembleDebug
```

## Development Phases

| Phase | Focus | Tests |
|-------|-------|-------|
| 1 | Initial app + core features | — |
| 2 | 3-axis evidence model refactor | — |
| 3 | Combo gating, 4-state verdicts, category whitelist | 92 |
| 4 | Red-team hardening, adversarial tests | 115 |
| 5 | Release refinements (stalkerware, rollback, installer, scoring) | 139 |
| 6 | Sleeping Sentinel prep (SpecialAccess, ConfigBaseline, Incidents, RootCause) | 213 |
| 7 | System app alarm-wall fix + domain-aware trust model | 859 |
| 8 | Negative tests, E2E pipeline, contract tests, static guards | 895 |

## License

MIT