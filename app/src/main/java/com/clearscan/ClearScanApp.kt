package com.clearscan

import android.app.Application

class ClearScanApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // Initialize private-file encryption before any document reader or writer is used.
        ImageProcessor.initialize(this)
        AppLogger.init(this)
        AppLogger.i("Application", "ClearScanApp started")
        // Remove plaintext passwords retained by previous releases.
        getSharedPreferences("clearscan-settings", MODE_PRIVATE)
            .edit()
            .remove("passwords")
            .apply()
        // Decrypted share/export staging files are temporary and never need to survive a restart.
        cacheDir.listFiles()
            ?.filter {
                it.name.startsWith("clear-doc-") ||
                    it.name.startsWith("clear-read-") ||
                    it.name.startsWith("clear-write-") ||
                    it.name.startsWith(".clear-doc-") ||
                    it.name.startsWith(".clear-read-") ||
                    it.name.startsWith(".clear-write-") ||
                    it.name.endsWith("-optimized.jpg") ||
                    it.name.startsWith("clearscan-capture-")
            }
            ?.forEach { it.delete() }
        val prefs = getSharedPreferences("clearscan-settings", MODE_PRIVATE)
        GitHubUpdateRepository.schedule(this, prefs.getBoolean("autoCheckUpdates", true), prefs.getBoolean("wifiOnlyUpdates", true))
    }
}
