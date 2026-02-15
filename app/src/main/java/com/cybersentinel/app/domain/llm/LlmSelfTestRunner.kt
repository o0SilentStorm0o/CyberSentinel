package com.cybersentinel.app.domain.llm

import com.cybersentinel.app.domain.explainability.EngineSource
import com.cybersentinel.app.domain.explainability.ExplanationRequest
import com.cybersentinel.app.domain.explainability.PolicyGuard
import com.cybersentinel.app.domain.explainability.TemplateExplanationEngine
import com.cybersentinel.app.domain.security.*

/**
 * LlmSelfTestRunner — debug-only benchmark harness for LLM pipeline quality assessment.
 *
 * Runs a set of fixture incidents through the full LLM pipeline and collects
 * aggregated metrics for the debug "LLM Self-Test" screen.
 *
 * This is NOT user-facing. It's the quality gate that tells us:
 *  1. Is the model producing valid structured slots?
 *  2. How often do we need SlotValidator repairs?
 *  3. How often do we fall back to template?
 *  4. What's the latency profile?
 *  5. Are there OOM/timeout issues?
 *
 * Usage:
 *   val runner = LlmSelfTestRunner(runtime, promptBuilder, slotParser, slotValidator, ...)
 *   val result = runner.runBenchmark(runs = 20)
 *   // Display result.summary in debug UI
 *
 * Design:
 *  - Fully deterministic with FakeLlmRuntime (for CI/tests)
 *  - Variable with real LlamaCppRuntime (for on-device benchmarking)
 *  - No side effects — doesn't modify app state
 *  - Doesn't store raw prompts or outputs (privacy)
 */
class LlmSelfTestRunner(
    private val runtime: LlmRuntime,
    private val promptBuilder: PromptBuilder,
    private val slotParser: SlotParser,
    private val slotValidator: SlotValidator,
    private val templateEngine: TemplateExplanationEngine,
    private val policyGuard: PolicyGuard,
    private val inferenceConfig: InferenceConfig = InferenceConfig.SLOTS_DEFAULT,
    /**
     * Optional native heap tracker. On real devices, pass { Debug.getNativeHeapAllocatedSize() }.
     * In unit tests, defaults to a no-op returning 0 (Debug API is stubbed).
     */
    private val nativeHeapBytesProvider: () -> Long = { 0L }
) {

    // ══════════════════════════════════════════════════════════
    //  Benchmark execution
    // ══════════════════════════════════════════════════════════

    /**
     * Run a full benchmark with the specified number of runs.
     *
     * Each run uses a fixture incident at a random severity level,
     * cycling through all severities evenly.
     *
     * @param runs Number of inference runs (default 20)
     * @param modelId Model identifier for the result
     * @param modelVersion Model version for the result
     * @return Complete benchmark result with aggregated metrics
     */
    fun runBenchmark(
        runs: Int = DEFAULT_RUNS,
        modelId: String = "unknown",
        modelVersion: String = "unknown"
    ): LlmBenchmarkResult {
        val startedAt = System.currentTimeMillis()
        val singleResults = mutableListOf<SingleRunResult>()
        val inferenceResults = mutableListOf<InferenceResult>()
        var peakNativeHeap = 0L

        val severities = IncidentSeverity.values()

        for (i in 0 until runs) {
            // Measure native heap before and after each run
            val heapBefore = nativeHeapBytesProvider()

            val severity = severities[i % severities.size]
            val result = runSingle(i, severity)
            singleResults.add(result)
            inferenceResults.add(result.inferenceResult)

            val heapAfter = nativeHeapBytesProvider()
            val heapMax = maxOf(heapBefore, heapAfter)
            if (heapMax > peakNativeHeap) peakNativeHeap = heapMax
        }

        val completedAt = System.currentTimeMillis()

        return LlmBenchmarkResult(
            modelId = modelId,
            modelVersion = modelVersion,
            runtimeId = runtime.runtimeId,
            totalRuns = runs,
            latency = LatencyMetrics.fromResults(inferenceResults),
            stability = StabilityMetrics.fromResults(inferenceResults),
            quality = computeQualityMetrics(singleResults),
            pipeline = computePipelineMetrics(singleResults),
            inferenceConfig = inferenceConfig,
            startedAt = startedAt,
            completedAt = completedAt,
            peakNativeHeapBytes = peakNativeHeap
        )
    }

    /**
     * Run a quick smoke test: 5 runs, one per severity.
     * Returns a simplified LlmSelfTestResult (backward-compatible with C2-1 model).
     */
    fun runSmokeTest(
        modelId: String = "unknown",
        modelVersion: String = "unknown"
    ): LlmSelfTestResult {
        val benchmark = runBenchmark(runs = 5, modelId = modelId, modelVersion = modelVersion)
        return LlmSelfTestResult(
            modelId = benchmark.modelId,
            modelVersion = benchmark.modelVersion,
            avgLatencyMs = benchmark.latency.avgMs,
            schemaComplianceRate = benchmark.quality.schemaComplianceRate,
            oomDetected = benchmark.stability.oomCount > 0,
            testRunCount = benchmark.totalRuns,
            successfulParses = (benchmark.quality.schemaComplianceRate * benchmark.totalRuns).toInt(),
            avgTokensPerSecond = benchmark.latency.avgTokensPerSecond
        )
    }

    // ══════════════════════════════════════════════════════════
    //  Single run execution
    // ══════════════════════════════════════════════════════════

    /**
     * Execute a single test run through the full pipeline.
     */
    internal fun runSingle(runIndex: Int, severity: IncidentSeverity): SingleRunResult {
        val incident = createFixtureIncident(severity)
        val constraints = policyGuard.determineConstraints(incident)
        val pipelineStart = System.currentTimeMillis()

        // Step 1: Build prompt
        val prompt = try {
            promptBuilder.buildPrompt(incident, constraints)
        } catch (e: Exception) {
            return SingleRunResult(
                runIndex = runIndex,
                severity = severity,
                inferenceResult = InferenceResult.failure("Prompt build failed: ${e.message}"),
                parseResult = null,
                validationResult = null,
                engineSource = EngineSource.LLM_FALLBACK_TO_TEMPLATE,
                totalPipelineMs = System.currentTimeMillis() - pipelineStart
            )
        }

        // Step 2: Run inference
        val inferenceResult = try {
            runtime.runInference(prompt, inferenceConfig)
        } catch (e: Exception) {
            return SingleRunResult(
                runIndex = runIndex,
                severity = severity,
                inferenceResult = InferenceResult.failure("Inference exception: ${e.message}"),
                parseResult = null,
                validationResult = null,
                engineSource = EngineSource.LLM_FALLBACK_TO_TEMPLATE,
                totalPipelineMs = System.currentTimeMillis() - pipelineStart
            )
        }

        if (!inferenceResult.success) {
            return SingleRunResult(
                runIndex = runIndex,
                severity = severity,
                inferenceResult = inferenceResult,
                parseResult = null,
                validationResult = null,
                engineSource = EngineSource.LLM_FALLBACK_TO_TEMPLATE,
                totalPipelineMs = System.currentTimeMillis() - pipelineStart
            )
        }

        // Step 3: Parse
        val parseResult = slotParser.parse(inferenceResult.rawOutput)
        if (!parseResult.isSuccess) {
            return SingleRunResult(
                runIndex = runIndex,
                severity = severity,
                inferenceResult = inferenceResult,
                parseResult = parseResult,
                validationResult = null,
                engineSource = EngineSource.LLM_FALLBACK_TO_TEMPLATE,
                totalPipelineMs = System.currentTimeMillis() - pipelineStart
            )
        }

        // Step 4: Validate (STRICT for benchmarking)
        val validationResult = slotValidator.validate(
            parseResult.slotsOrNull!!,
            incident,
            ValidationMode.STRICT
        )

        val engineSource = if (validationResult.isUsable) {
            EngineSource.LLM_ASSISTED
        } else {
            EngineSource.LLM_FALLBACK_TO_TEMPLATE
        }

        return SingleRunResult(
            runIndex = runIndex,
            severity = severity,
            inferenceResult = inferenceResult,
            parseResult = parseResult,
            validationResult = validationResult,
            engineSource = engineSource,
            totalPipelineMs = System.currentTimeMillis() - pipelineStart
        )
    }

    // ══════════════════════════════════════════════════════════
    //  Metric computation
    // ══════════════════════════════════════════════════════════

    private fun computeQualityMetrics(results: List<SingleRunResult>): QualityMetrics {
        if (results.isEmpty()) return QualityMetrics.EMPTY

        val total = results.size.toFloat()
        var strictPassCount = 0
        var faithfulCount = 0
        var policyViolations = 0
        var repairedCount = 0
        var rejectedCount = 0
        val confidences = mutableListOf<Double>()

        for (r in results) {
            val validationResult = r.validationResult ?: continue

            when (validationResult) {
                is ValidationResult.Valid -> {
                    strictPassCount++
                    confidences.add(validationResult.slots.confidence)
                }
                is ValidationResult.Repaired -> {
                    repairedCount++
                    confidences.add(validationResult.slots.confidence)
                }
                is ValidationResult.Rejected -> {
                    rejectedCount++
                }
            }

            // Evidence faithfulness: check if all reason_ids are from incident
            val slots = validationResult.slotsOrNull
            if (slots != null) {
                val incident = createFixtureIncident(r.severity)
                val validIds = collectEvidenceIds(incident)
                if (slots.selectedEvidenceIds.all { it in validIds }) {
                    faithfulCount++
                }
            }
        }

        val parsedCount = results.count { it.parseResult?.isSuccess == true }

        return QualityMetrics(
            schemaComplianceRate = strictPassCount / total,
            evidenceFaithfulnessRate = if (parsedCount > 0) faithfulCount.toFloat() / parsedCount else 0f,
            policyViolationCount = policyViolations,
            avgConfidence = if (confidences.isNotEmpty()) confidences.average() else 0.0,
            repairedCount = repairedCount,
            rejectedCount = rejectedCount
        )
    }

    private fun computePipelineMetrics(results: List<SingleRunResult>): PipelineMetrics {
        if (results.isEmpty()) return PipelineMetrics.EMPTY

        val total = results.size.toFloat()
        val inferenceSuccess = results.count { it.inferenceResult.success }
        val parseSuccess = results.count { it.parseResult?.isSuccess == true }
        val validatePass = results.count { it.validationResult?.isUsable == true }
        val validateRepaired = results.count { it.validationResult is ValidationResult.Repaired }
        val fallback = results.count { it.wasFallback }

        return PipelineMetrics(
            inferenceSuccessRate = inferenceSuccess / total,
            parseSuccessRate = parseSuccess / total,
            validatePassRate = validatePass / total,
            validateRepairRate = if (parseSuccess > 0) validateRepaired.toFloat() / parseSuccess else 0f,
            templateFallbackRate = fallback / total
        )
    }

    private fun collectEvidenceIds(incident: SecurityIncident): Set<String> {
        val ids = mutableSetOf<String>()
        for (event in incident.events) {
            ids.add(event.id)
            for (signal in event.signals) ids.add(signal.id)
        }
        return ids
    }

    // ══════════════════════════════════════════════════════════
    //  Fixture incidents
    // ══════════════════════════════════════════════════════════

    /**
     * Create a representative fixture incident for a given severity level.
     * Uses realistic signal/event types to exercise the full pipeline.
     */
    internal fun createFixtureIncident(severity: IncidentSeverity): SecurityIncident {
        val (eventType, signalTypes, pkg) = when (severity) {
            IncidentSeverity.CRITICAL -> Triple(
                EventType.DEVICE_COMPROMISE,
                listOf(SignalType.CERT_CHANGE to "cert-change-001", SignalType.VERSION_ROLLBACK to "rollback-002"),
                "com.suspicious.malware"
            )
            IncidentSeverity.HIGH -> Triple(
                EventType.SUSPICIOUS_UPDATE,
                listOf(SignalType.CERT_CHANGE to "cert-upd-001", SignalType.HIGH_RISK_PERM_ADDED to "perm-new-002"),
                "com.example.update"
            )
            IncidentSeverity.MEDIUM -> Triple(
                EventType.CAPABILITY_ESCALATION,
                listOf(SignalType.HIGH_RISK_PERM_ADDED to "perm-esc-001"),
                "com.example.app"
            )
            IncidentSeverity.LOW -> Triple(
                EventType.SUSPICIOUS_INSTALL,
                listOf(SignalType.NEW_APP_INSTALLED to "sideload-001"),
                "com.developer.tool"
            )
            IncidentSeverity.INFO -> Triple(
                EventType.OTHER,
                listOf(SignalType.NEW_APP_INSTALLED to "install-001"),
                "com.safe.app"
            )
        }

        val signals = signalTypes.map { (type, id) ->
            SecuritySignal(
                id = id,
                source = SignalSource.APP_SCANNER,
                type = type,
                severity = when (severity) {
                    IncidentSeverity.CRITICAL -> SignalSeverity.CRITICAL
                    IncidentSeverity.HIGH -> SignalSeverity.HIGH
                    IncidentSeverity.MEDIUM -> SignalSeverity.MEDIUM
                    IncidentSeverity.LOW -> SignalSeverity.LOW
                    IncidentSeverity.INFO -> SignalSeverity.INFO
                },
                packageName = pkg,
                summary = "Fixture signal for $type"
            )
        }

        val event = SecurityEvent(
            source = SignalSource.APP_SCANNER,
            type = eventType,
            severity = signals.first().severity,
            packageName = pkg,
            summary = "Fixture event for $eventType",
            signals = signals
        )

        return SecurityIncident(
            severity = severity,
            title = "Fixture ${severity.name} incident",
            summary = "Self-test fixture for ${severity.name}",
            packageName = pkg,
            events = listOf(event),
            hypotheses = listOf(
                Hypothesis(
                    name = "fixture_hypothesis",
                    description = "Test hypothesis for ${severity.name}",
                    confidence = 0.7,
                    supportingEvidence = signals.map { it.id }
                )
            ),
            recommendedActions = listOf(
                RecommendedAction(
                    priority = 1,
                    type = ActionCategory.CHECK_SETTINGS,
                    title = "Check",
                    description = "Fixture action",
                    targetPackage = pkg
                ),
                RecommendedAction(
                    priority = 2,
                    type = ActionCategory.MONITOR,
                    title = "Monitor",
                    description = "Fixture monitoring",
                    targetPackage = pkg
                )
            )
        )
    }

    companion object {
        const val DEFAULT_RUNS = 20
    }
}
