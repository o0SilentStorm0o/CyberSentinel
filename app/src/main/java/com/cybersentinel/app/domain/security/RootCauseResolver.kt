package com.cybersentinel.app.domain.security

/**
 * RootCauseResolver — ranks hypotheses explaining WHY a security event happened.
 *
 * Input: anomaly signal + app knowledge (feature vector) + device config
 * Output: SecurityIncident with ranked hypotheses
 *
 * Design principles:
 *  1. Deterministic — same inputs = same hypotheses, same ranking
 *  2. Evidence-based — every hypothesis has supporting and contradicting evidence
 *  3. Confidence-scored — 0.0–1.0, sorted descending
 *  4. Actionable — each incident includes recommended actions
 *
 * This is an INTERFACE — implementation follows when incident pipeline is active.
 */
interface RootCauseResolver {

    /**
     * Analyze a security event using app knowledge and config context.
     * Produces ranked hypotheses explaining the root cause.
     *
     * @param event The security event to analyze
     * @param appKnowledge Feature vector for the affected app (null for device-level events)
     * @param configSnapshot Current device configuration (null if not available)
     * @param recentEvents Recent events for correlation (last 24h recommended)
     * @return SecurityIncident with ranked hypotheses and recommended actions
     */
    fun resolve(
        event: SecurityEvent,
        appKnowledge: AppFeatureVector? = null,
        configSnapshot: ConfigBaselineEngine.ConfigSnapshot? = null,
        recentEvents: List<SecurityEvent> = emptyList()
    ): SecurityIncident

    /**
     * Batch-resolve multiple events — may find cross-event correlations.
     * For example: "same time, same attacker" pattern.
     *
     * @return List of incidents, potentially merging related events
     */
    fun resolveAll(
        events: List<SecurityEvent>,
        appKnowledge: Map<String, AppFeatureVector> = emptyMap(),
        configSnapshot: ConfigBaselineEngine.ConfigSnapshot? = null
    ): List<SecurityIncident>
}

/**
 * Default implementation — deterministic hypothesis scoring.
 *
 * Scoring rules:
 *  - Base confidence from event severity
 *  - Boosted by corroborating signals (same app, same timeframe)
 *  - Reduced by contradicting evidence (e.g., high trust)
 *  - Bounded to [0.0, 1.0]
 */
class DefaultRootCauseResolver : RootCauseResolver {

    override fun resolve(
        event: SecurityEvent,
        appKnowledge: AppFeatureVector?,
        configSnapshot: ConfigBaselineEngine.ConfigSnapshot?,
        recentEvents: List<SecurityEvent>
    ): SecurityIncident {
        val hypotheses = generateHypotheses(event, appKnowledge, configSnapshot, recentEvents)
            .sortedByDescending { it.confidence }

        val topHypothesis = hypotheses.firstOrNull()
        val severity = mapSeverity(event.severity)
        val actions = generateActions(event, appKnowledge, topHypothesis)

        return SecurityIncident(
            severity = severity,
            title = topHypothesis?.name ?: event.summary,
            summary = topHypothesis?.description ?: event.summary,
            packageName = event.packageName,
            affectedPackages = listOfNotNull(event.packageName),
            events = listOf(event),
            hypotheses = hypotheses,
            recommendedActions = actions
        )
    }

    override fun resolveAll(
        events: List<SecurityEvent>,
        appKnowledge: Map<String, AppFeatureVector>,
        configSnapshot: ConfigBaselineEngine.ConfigSnapshot?
    ): List<SecurityIncident> {
        // Group events by package, then resolve each group
        val byPackage = events.groupBy { it.packageName ?: "__device__" }
        return byPackage.flatMap { (pkg, pkgEvents) ->
            val knowledge = if (pkg != "__device__") appKnowledge[pkg] else null
            val recentOther = events - pkgEvents.toSet()
            pkgEvents.map { event ->
                resolve(event, knowledge, configSnapshot, recentOther)
            }
        }
    }

    // ──────────────────────────────────────────────────────────
    //  Hypothesis generation
    // ──────────────────────────────────────────────────────────

    private fun generateHypotheses(
        event: SecurityEvent,
        app: AppFeatureVector?,
        config: ConfigBaselineEngine.ConfigSnapshot?,
        recentEvents: List<SecurityEvent>
    ): List<Hypothesis> {
        val hypotheses = mutableListOf<Hypothesis>()

        when (event.type) {
            EventType.STALKERWARE_PATTERN -> {
                hypotheses.add(buildStalkerwareHypothesis(event, app))
            }
            EventType.DROPPER_PATTERN -> {
                hypotheses.add(buildDropperHypothesis(event, app))
            }
            EventType.SUSPICIOUS_UPDATE -> {
                hypotheses.add(buildSupplyChainHypothesis(event, app))
                hypotheses.add(buildLegitimateUpdateHypothesis(event, app))
            }
            EventType.CAPABILITY_ESCALATION -> {
                hypotheses.add(buildEscalationHypothesis(event, app))
                hypotheses.add(buildFeatureAddHypothesis(event, app))
            }
            EventType.SPECIAL_ACCESS_GRANT -> {
                hypotheses.add(buildMaliciousAccessHypothesis(event, app))
                hypotheses.add(buildLegitimateAccessHypothesis(event, app))
            }
            EventType.CONFIG_TAMPER -> {
                hypotheses.add(buildConfigTamperHypothesis(event, config))
            }
            EventType.CA_CERT_INSTALLED -> {
                hypotheses.add(buildMitmHypothesis(event, config))
                hypotheses.add(buildCorporateHypothesis(event, config))
            }
            EventType.OVERLAY_ATTACK_PATTERN -> {
                hypotheses.add(buildOverlayAttackHypothesis(event, app))
                hypotheses.add(buildBankingOverlayHypothesis(event, app))
            }
            EventType.STAGED_PAYLOAD -> {
                hypotheses.add(buildStagedPayloadHypothesis(event, app))
                hypotheses.add(buildDropperHypothesis(event, app))
            }
            EventType.LOADER_BEHAVIOR -> {
                hypotheses.add(buildLoaderBehaviorHypothesis(event, app))
                hypotheses.add(buildGenericHypothesis(event, app))
            }
            else -> {
                hypotheses.add(buildGenericHypothesis(event, app))
            }
        }

        // Cross-event correlation boost
        val sameAppEvents = recentEvents.filter { it.packageName == event.packageName }
        if (sameAppEvents.size >= 2) {
            hypotheses.forEach { h ->
                // Boost confidence if multiple recent events for same app
                val boostedConfidence = (h.confidence + 0.1).coerceAtMost(1.0)
                hypotheses[hypotheses.indexOf(h)] = h.copy(
                    confidence = boostedConfidence,
                    supportingEvidence = h.supportingEvidence + "Více bezpečnostních událostí pro tuto aplikaci v krátké době"
                )
            }
        }

        return hypotheses
    }

    // ── Hypothesis builders ──

    private fun buildStalkerwareHypothesis(event: SecurityEvent, app: AppFeatureVector?): Hypothesis {
        val evidence = mutableListOf("Kombinace accessibility + čtení notifikací")
        val contradicting = mutableListOf<String>()
        var confidence = 0.7

        if (app != null) {
            if (app.identity.installerType == TrustEvidenceEngine.InstallerType.SIDELOADED) {
                evidence.add("Sideloaded instalace")
                confidence += 0.15
            }
            if (app.identity.trustScore < 40) {
                evidence.add("Nízká důvěra (${app.identity.trustScore})")
                confidence += 0.1
            } else {
                contradicting.add("Vyšší důvěra (${app.identity.trustScore})")
                confidence -= 0.15
            }
        }

        return Hypothesis(
            name = "Stalkerware / sledovací aplikace",
            description = "Aplikace má schopnosti typické pro sledovací software",
            confidence = confidence.coerceIn(0.0, 1.0),
            supportingEvidence = evidence,
            contradictingEvidence = contradicting,
            mitreTechniques = listOf("T1417", "T1513") // Input Capture, Screen Capture
        )
    }

    private fun buildDropperHypothesis(event: SecurityEvent, app: AppFeatureVector?): Hypothesis {
        var confidence = 0.6
        val evidence = mutableListOf("Accessibility + instalace balíčků")
        val contradicting = mutableListOf<String>()

        if (app != null) {
            if (app.identity.trustScore < 40) {
                confidence += 0.15
                evidence.add("Nízká důvěra (${app.identity.trustScore})")
            }
            if (app.identity.installerType == TrustEvidenceEngine.InstallerType.SIDELOADED) {
                confidence += 0.1
                evidence.add("Sideloaded instalace")
            }
            if (app.identity.isNewApp) {
                confidence += 0.1
                evidence.add("Čerstvě nainstalovaná aplikace")
            }
            // Check for overlay (dropper with banking attack vector)
            val hasOverlay = app.capability.activeHighRiskClusters.any {
                it == TrustRiskModel.CapabilityCluster.OVERLAY
            }
            if (hasOverlay) {
                confidence += 0.1
                evidence.add("Overlay oprávnění — možný bankovní útok")
            }
            if (app.identity.trustScore >= 70) {
                contradicting.add("Vyšší důvěra (${app.identity.trustScore})")
                confidence -= 0.2
            }
        }

        return Hypothesis(
            name = "Dropper / instalátor malware",
            description = "Aplikace může automaticky instalovat škodlivé balíčky",
            confidence = confidence.coerceIn(0.0, 1.0),
            supportingEvidence = evidence,
            contradictingEvidence = contradicting,
            mitreTechniques = listOf("T1544") // Ingress Tool Transfer
        )
    }

    private fun buildSupplyChainHypothesis(event: SecurityEvent, app: AppFeatureVector?): Hypothesis {
        var confidence = 0.4
        val evidence = mutableListOf("Podezřelá aktualizace")
        if (app?.change?.isVersionRollback == true) {
            confidence += 0.3
            evidence.add("Verze šla dolů (rollback)")
        }
        return Hypothesis(
            name = "Supply-chain útok",
            description = "Aktualizace aplikace mohla být kompromitována",
            confidence = confidence.coerceIn(0.0, 1.0),
            supportingEvidence = evidence,
            mitreTechniques = listOf("T1195") // Supply Chain Compromise
        )
    }

    private fun buildLegitimateUpdateHypothesis(event: SecurityEvent, app: AppFeatureVector?): Hypothesis {
        var confidence = 0.3
        val evidence = mutableListOf<String>()
        if (app?.identity?.trustScore ?: 0 >= 70) {
            confidence += 0.4
            evidence.add("Vysoká důvěra vývojáři")
        }
        return Hypothesis(
            name = "Legitimní aktualizace",
            description = "Standardní aktualizace od známého vývojáře",
            confidence = confidence.coerceIn(0.0, 1.0),
            supportingEvidence = evidence
        )
    }

    private fun buildEscalationHypothesis(event: SecurityEvent, app: AppFeatureVector?): Hypothesis {
        return Hypothesis(
            name = "Eskalace oprávnění",
            description = "Aplikace získala nové nebezpečné schopnosti",
            confidence = 0.5,
            supportingEvidence = listOf("Přidána nová riziková oprávnění"),
            mitreTechniques = listOf("T1548") // Abuse Elevation Control Mechanism
        )
    }

    private fun buildFeatureAddHypothesis(event: SecurityEvent, app: AppFeatureVector?): Hypothesis {
        var confidence = 0.3
        if (app?.identity?.trustScore ?: 0 >= 70) confidence += 0.3
        return Hypothesis(
            name = "Přidání nových funkcí",
            description = "Vývojář přidal nové funkce vyžadující oprávnění",
            confidence = confidence.coerceIn(0.0, 1.0),
            supportingEvidence = listOf("Běžný vývoj aplikací")
        )
    }

    private fun buildMaliciousAccessHypothesis(event: SecurityEvent, app: AppFeatureVector?): Hypothesis {
        var confidence = 0.4
        val evidence = mutableListOf("Speciální přístup povolen")
        if (app?.identity?.installerType == TrustEvidenceEngine.InstallerType.SIDELOADED) {
            confidence += 0.2
            evidence.add("Sideloaded aplikace")
        }
        return Hypothesis(
            name = "Škodlivé zneužití speciálního přístupu",
            description = "Speciální přístup může být zneužit ke sledování nebo manipulaci",
            confidence = confidence.coerceIn(0.0, 1.0),
            supportingEvidence = evidence,
            mitreTechniques = listOf("T1628") // Hide Artifacts
        )
    }

    private fun buildLegitimateAccessHypothesis(event: SecurityEvent, app: AppFeatureVector?): Hypothesis {
        var confidence = 0.3
        if (app?.identity?.trustScore ?: 0 >= 70) confidence += 0.4
        return Hypothesis(
            name = "Legitimní speciální přístup",
            description = "Uživatel povolil přístup pro důvěryhodnou aplikaci",
            confidence = confidence.coerceIn(0.0, 1.0),
            supportingEvidence = listOf("Uživatelem povoleno")
        )
    }

    private fun buildConfigTamperHypothesis(event: SecurityEvent, config: ConfigBaselineEngine.ConfigSnapshot?): Hypothesis {
        return Hypothesis(
            name = "Manipulace s konfigurací zařízení",
            description = "Nastavení zařízení bylo změněno způsobem, který může ohrozit bezpečnost",
            confidence = 0.5,
            supportingEvidence = listOf("Změna konfigurace detekována")
        )
    }

    private fun buildMitmHypothesis(event: SecurityEvent, config: ConfigBaselineEngine.ConfigSnapshot?): Hypothesis {
        var confidence = 0.5
        val evidence = mutableListOf("Uživatelský CA certifikát nainstalován")
        if (config?.vpnActive == true) {
            confidence += 0.2
            evidence.add("VPN aktivní současně")
        }
        return Hypothesis(
            name = "Man-in-the-Middle odposlech",
            description = "CA certifikát umožňuje odposlech šifrované komunikace",
            confidence = confidence.coerceIn(0.0, 1.0),
            supportingEvidence = evidence,
            mitreTechniques = listOf("T1557") // Adversary-in-the-Middle
        )
    }

    private fun buildCorporateHypothesis(event: SecurityEvent, config: ConfigBaselineEngine.ConfigSnapshot?): Hypothesis {
        return Hypothesis(
            name = "Firemní/MDM konfigurace",
            description = "CA certifikát byl nainstalován pro firemní účely",
            confidence = 0.4,
            supportingEvidence = listOf("Běžné ve firemním prostředí")
        )
    }

    private fun buildOverlayAttackHypothesis(event: SecurityEvent, app: AppFeatureVector?): Hypothesis {
        var confidence = 0.6
        val evidence = mutableListOf("Overlay + nízká důvěra")
        val contradicting = mutableListOf<String>()
        if (app?.identity?.installerType == TrustEvidenceEngine.InstallerType.SIDELOADED) {
            confidence += 0.15
            evidence.add("Sideloaded aplikace")
        }
        if (app?.identity?.trustScore ?: 100 < 40) {
            confidence += 0.1
            evidence.add("Nízká důvěra (${app?.identity?.trustScore})")
        }
        if (app?.identity?.trustScore ?: 0 >= 70) {
            contradicting.add("Vyšší důvěra (${app?.identity?.trustScore})")
            confidence -= 0.2
        }
        return Hypothesis(
            name = "Overlay / phishing útok",
            description = "Aplikace může překrýt jiné aplikace falešným UI",
            confidence = confidence.coerceIn(0.0, 1.0),
            supportingEvidence = evidence,
            contradictingEvidence = contradicting,
            mitreTechniques = listOf("T1660") // Phishing
        )
    }

    private fun buildBankingOverlayHypothesis(event: SecurityEvent, app: AppFeatureVector?): Hypothesis {
        var confidence = 0.45
        val evidence = mutableListOf("Overlay oprávnění s podezřelým profilem")
        val contradicting = mutableListOf<String>()

        if (app != null) {
            // Accessibility + overlay = banking trojan signature
            val hasAccessibility = app.capability.activeHighRiskClusters.any {
                it == TrustRiskModel.CapabilityCluster.ACCESSIBILITY
            }
            if (hasAccessibility) {
                confidence += 0.2
                evidence.add("Accessibility + overlay = bankovní trojský kůň")
            }
            if (app.identity.installerType == TrustEvidenceEngine.InstallerType.SIDELOADED) {
                confidence += 0.15
                evidence.add("Sideloaded instalace")
            }
            if (app.identity.trustScore < 40) {
                confidence += 0.1
                evidence.add("Nízká důvěra (${app.identity.trustScore})")
            }
            if (app.identity.isNewApp) {
                confidence += 0.1
                evidence.add("Čerstvě nainstalovaná aplikace")
            }
            if (app.identity.trustScore >= 70) {
                contradicting.add("Vyšší důvěra (${app.identity.trustScore})")
                confidence -= 0.25
            }
        }

        return Hypothesis(
            name = "Bankovní overlay útok",
            description = "Aplikace vykazuje vzor bankovního trojského koně — overlay nad finančními aplikacemi",
            confidence = confidence.coerceIn(0.0, 1.0),
            supportingEvidence = evidence,
            contradictingEvidence = contradicting,
            mitreTechniques = listOf("T1660", "T1417") // Phishing, Input Capture
        )
    }

    private fun buildStagedPayloadHypothesis(event: SecurityEvent, app: AppFeatureVector?): Hypothesis {
        var confidence = 0.55
        val evidence = mutableListOf("Časový vzor instalace → eskalace oprávnění")
        val contradicting = mutableListOf<String>()

        if (app != null) {
            // Fresh install + capability acquisition = staged payload
            if (app.identity.isNewApp) {
                confidence += 0.15
                evidence.add("Čerstvě nainstalovaná aplikace")
            }
            val hasInstallPackages = app.capability.activeHighRiskClusters.any {
                it == TrustRiskModel.CapabilityCluster.INSTALL_PACKAGES
            }
            if (hasInstallPackages) {
                confidence += 0.15
                evidence.add("Oprávnění k instalaci dalších aplikací")
            }
            if (app.identity.installerType == TrustEvidenceEngine.InstallerType.SIDELOADED) {
                confidence += 0.1
                evidence.add("Sideloaded instalace")
            }
            if (app.identity.trustScore < 40) {
                confidence += 0.1
                evidence.add("Nízká důvěra (${app.identity.trustScore})")
            }
            if (app.identity.trustScore >= 70) {
                contradicting.add("Vyšší důvěra aplikace")
                confidence -= 0.25
            }
        }

        return Hypothesis(
            name = "Staged payload / dropper v fázích",
            description = "Aplikace se nejprve tvářila nevinně a následně eskalovala oprávnění — vzor staged dropperu",
            confidence = confidence.coerceIn(0.0, 1.0),
            supportingEvidence = evidence,
            contradictingEvidence = contradicting,
            mitreTechniques = listOf("T1544", "T1407") // Ingress Tool Transfer, Download New Code at Runtime
        )
    }

    private fun buildLoaderBehaviorHypothesis(event: SecurityEvent, app: AppFeatureVector?): Hypothesis {
        var confidence = 0.5
        val evidence = mutableListOf("Detekováno dynamické načítání kódu po instalaci")
        val contradicting = mutableListOf<String>()

        if (app != null) {
            if (app.identity.isNewApp) {
                confidence += 0.15
                evidence.add("Čerstvě nainstalovaná aplikace")
            }
            if (app.identity.installerType == TrustEvidenceEngine.InstallerType.SIDELOADED) {
                confidence += 0.15
                evidence.add("Sideloaded instalace")
            }
            if (app.identity.trustScore < 40) {
                confidence += 0.1
                evidence.add("Nízká důvěra (${app.identity.trustScore})")
            }
            // Network burst + dynamic loading = classic loader
            val hasNetworkBurst = event.signals.any {
                it.type == SignalType.NETWORK_BURST_ANOMALY ||
                it.type == SignalType.NETWORK_AFTER_INSTALL
            }
            if (hasNetworkBurst) {
                confidence += 0.15
                evidence.add("Síťový provoz po instalaci — stahování payloadu")
            }
            if (app.identity.trustScore >= 70) {
                contradicting.add("Vyšší důvěra aplikace")
                confidence -= 0.2
            }
        }

        return Hypothesis(
            name = "Loader / dynamický downloader",
            description = "Aplikace se chová jako loader — stahuje a spouští kód za běhu",
            confidence = confidence.coerceIn(0.0, 1.0),
            supportingEvidence = evidence,
            contradictingEvidence = contradicting,
            mitreTechniques = listOf("T1407", "T1544") // Download New Code at Runtime, Ingress Tool Transfer
        )
    }

    private fun buildGenericHypothesis(event: SecurityEvent, app: AppFeatureVector?): Hypothesis {
        return Hypothesis(
            name = "Bezpečnostní anomálie",
            description = event.summary,
            confidence = 0.3,
            supportingEvidence = listOf("Automaticky detekováno")
        )
    }

    // ──────────────────────────────────────────────────────────
    //  Action generation
    // ──────────────────────────────────────────────────────────

    private fun generateActions(
        event: SecurityEvent,
        app: AppFeatureVector?,
        topHypothesis: Hypothesis?
    ): List<RecommendedAction> {
        val actions = mutableListOf<RecommendedAction>()

        if (topHypothesis?.confidence ?: 0.0 > 0.7) {
            // High confidence — suggest strong action
            event.packageName?.let { pkg ->
                actions.add(RecommendedAction(
                    priority = 1,
                    type = ActionCategory.UNINSTALL,
                    title = "Odinstalovat aplikaci",
                    description = "Doporučujeme odinstalovat tuto podezřelou aplikaci",
                    targetPackage = pkg
                ))
            }
        }

        if (app?.hasActiveSpecialAccess == true) {
            event.packageName?.let { pkg ->
                actions.add(RecommendedAction(
                    priority = 2,
                    type = ActionCategory.REVOKE_SPECIAL_ACCESS,
                    title = "Odebrat speciální přístup",
                    description = "Zakažte speciální přístup v nastavení",
                    targetPackage = pkg
                ))
            }
        }

        if (event.type in setOf(EventType.CONFIG_TAMPER, EventType.CA_CERT_INSTALLED)) {
            actions.add(RecommendedAction(
                priority = 1,
                type = ActionCategory.CHECK_SETTINGS,
                title = "Zkontrolovat nastavení",
                description = "Zkontrolujte bezpečnostní nastavení zařízení"
            ))
        }

        // Always add monitoring as fallback
        actions.add(RecommendedAction(
            priority = actions.size + 1,
            type = ActionCategory.MONITOR,
            title = "Sledovat",
            description = "Sledovat tuto aplikaci/situaci při dalších skenech"
        ))

        return actions
    }

    private fun mapSeverity(signalSeverity: SignalSeverity): IncidentSeverity = when (signalSeverity) {
        SignalSeverity.CRITICAL -> IncidentSeverity.CRITICAL
        SignalSeverity.HIGH -> IncidentSeverity.HIGH
        SignalSeverity.MEDIUM -> IncidentSeverity.MEDIUM
        SignalSeverity.LOW -> IncidentSeverity.LOW
        SignalSeverity.INFO -> IncidentSeverity.INFO
    }
}
