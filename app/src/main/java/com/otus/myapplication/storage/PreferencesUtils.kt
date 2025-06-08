package com.otus.myapplication.storage

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

private const val sharedPrefsFile: String = "securePref"

class PreferencesUtils(
    private val applicationContext: Context,
    private val mainKey: MasterKey
) {

    private val sharedPreferences by lazy {
        EncryptedSharedPreferences.create(
            applicationContext,
            sharedPrefsFile,
            mainKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    fun set(key: String, value: String) {
        with(sharedPreferences.edit()) {
            putString(key, value)
            apply()
        }
    }

    fun get(key: String): String {
        return sharedPreferences.getString(key, "").orEmpty()
    }

    fun setAuthToken(token: String, key: javax.crypto.SecretKey) {
        val encrypted = com.otus.myapplication.crypto.Security().encryptAes(token, key)
        set("auth_token", encrypted)
    }

    fun getAuthToken(key: javax.crypto.SecretKey): String? {
        val encrypted = get("auth_token")
        if (encrypted.isEmpty()) return null
        return com.otus.myapplication.crypto.Security().decryptAes(encrypted, key)
    }

    fun setBiometryEnabled(enabled: Boolean) {
        set("biometry_enabled", enabled.toString())
    }

    fun isBiometryEnabled(): Boolean {
        return get("biometry_enabled") == "true"
    }
}