package com.cybersentinel.app


import android.app.Application
import com.cybersentinel.app.workers.CveCheckWorker
import dagger.hilt.android.HiltAndroidApp


@HiltAndroidApp
class CyberSentinelApp : Application() {
    
    override fun onCreate() {
        super.onCreate()
        // Schedule background CVE checks
        CveCheckWorker.schedule(this)
    }
}