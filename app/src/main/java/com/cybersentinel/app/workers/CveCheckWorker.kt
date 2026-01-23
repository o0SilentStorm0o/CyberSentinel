package com.cybersentinel.app.workers

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.hilt.work.HiltWorker
import androidx.work.*
import com.cybersentinel.app.R
import com.cybersentinel.app.data.repo.CveRepository
import com.cybersentinel.app.data.kev.KevCatalog
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject

@HiltWorker
class CveCheckWorker @AssistedInject constructor(
    @Assisted appCtx: Context,
    @Assisted params: WorkerParameters,
    private val repo: CveRepository,
    private val kevCatalog: KevCatalog,
) : CoroutineWorker(appCtx, params) {

    override suspend fun doWork(): Result {
        return try {
            // Refresh KEV catalog if stale
            kevCatalog.refreshIfStale()
            
            // Fetch latest 7 days relevant (network + cache)
            val fresh = repo.searchNvdForDevice(
                daysBack = 7,
                page = 0,
                pageSize = 50,
                profile = repo.getDeviceProfile() // We'll add this method
            ).filter { item ->
                // High score or KEV
                val isKev = kevCatalog.isKev(item.id)
                val highScore = item.cvss != null && item.cvss!! >= 7.0
                (isKev || highScore) && !repo.isAcknowledged(item.id)
            }

            if (fresh.isNotEmpty()) {
                notifyTop(fresh.take(3).map { it.id to it.summary })
            }
            Result.success()
        } catch (e: Exception) {
            Result.retry()
        }
    }

    private fun notifyTop(list: List<Pair<String,String>>) {
        createChannel()
        val text = list.joinToString("\n") { "${it.first}: ${it.second}" }
        val n = NotificationCompat.Builder(applicationContext, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert) // Fallback icon
            .setContentTitle("New critical Android CVEs")
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .build()
        NotificationManagerCompat.from(applicationContext).notify(42, n)
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            val chan = NotificationChannel(
                CHANNEL_ID, "CyberSentinel Alerts",
                NotificationManager.IMPORTANCE_HIGH
            )
            val nm = applicationContext.getSystemService(NotificationManager::class.java)
            nm?.createNotificationChannel(chan)
        }
    }

    companion object {
        private const val CHANNEL_ID = "cve_alerts"

        fun schedule(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .setRequiresBatteryNotLow(true)
                .build()

            val req = PeriodicWorkRequestBuilder<CveCheckWorker>(24, java.util.concurrent.TimeUnit.HOURS)
                .setConstraints(constraints)
                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                "cve-check",
                ExistingPeriodicWorkPolicy.UPDATE,
                req
            )
        }
    }
}