package com.otus.myapplication

import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.BIOMETRIC_SUCCESS
import androidx.biometric.auth.AuthPromptErrorException
import androidx.biometric.auth.AuthPromptFailureException
import androidx.biometric.auth.AuthPromptHost
import androidx.biometric.auth.Class2BiometricAuthPrompt
import androidx.biometric.auth.Class3BiometricAuthPrompt
import androidx.biometric.auth.authenticate
import androidx.lifecycle.lifecycleScope
import androidx.security.crypto.MasterKey
import com.otus.myapplication.biometrics.BiometricCipher
import com.otus.myapplication.crypto.Keys
import com.otus.myapplication.crypto.Security
import com.otus.myapplication.databinding.ActivityMainBinding
import com.otus.myapplication.storage.PreferencesUtils
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        java.security.Security.getProviders()

        val secure = Security()
        val keys = Keys(applicationContext)
        val masterKey = keys.getMasterKey(MasterKey.KeyScheme.AES256_GCM)

        binding.hashMd5Button.setOnClickListener {
            val text = binding.hashText.text.toString()
            val hash = secure.md5(text)
            Toast.makeText(this, hash, Toast.LENGTH_LONG).show()
        }
        binding.hashSha256Button.setOnClickListener {
            val text = binding.hashText.text.toString()
            val hash = secure.sha256(text)
            Toast.makeText(this, hash, Toast.LENGTH_LONG).show()
        }

        val key = keys.getAesSecretKey()
        binding.cryptoEncryptButton.setOnClickListener {
            val text = binding.cryptoText.text.toString()
            val encryptedText = secure.encryptAes(text, key)
            binding.cryptoText.setText(encryptedText)

        }
        binding.cryptoDecryptButton.setOnClickListener {
            val text = binding.cryptoText.text.toString()
            val decryptedText = secure.decryptAes(text, key)
            binding.cryptoText.setText(decryptedText)
        }

        val preferences = PreferencesUtils(applicationContext, masterKey)
        binding.setPreferenceButton.setOnClickListener {
            val value = binding.storageText.text
            preferences.set("key", value.toString())
        }
        binding.getPreferenceButton.setOnClickListener {
            binding.storageText.setText(preferences.get("key"))
        }

        binding.weakBiometryButton.setOnClickListener {
            val success = BiometricManager.from(this)
                .canAuthenticate(BIOMETRIC_WEAK) == BIOMETRIC_SUCCESS
            if (success) {
                val authPrompt = Class2BiometricAuthPrompt.Builder("Weak biometry", "dismiss").apply {
                    setSubtitle("Input your biometry")
                    setDescription("We need your finger")
                    setConfirmationRequired(true)
                }.build()

                lifecycleScope.launch {
                    try {
                        authPrompt.authenticate(AuthPromptHost(this@MainActivity))
                        Log.d("It works", "Hello from biometry")
                    } catch (e: AuthPromptErrorException) {
                        Log.e("AuthPromptError", e.message ?: "no message")
                    } catch (e: AuthPromptFailureException) {
                        Log.e("AuthPromptFailure", e.message ?: "no message")
                    }
                }
            } else {
                Toast.makeText(this, "Biometry not supported", Toast.LENGTH_LONG).show()
            }
        }
        binding.strongBiometryButton.setOnClickListener {
            val success = BiometricManager.from(this)
                .canAuthenticate(BIOMETRIC_STRONG) == BIOMETRIC_SUCCESS
            if (success) {
                val biometricCipher = BiometricCipher(this.applicationContext)
                val encryptor = biometricCipher.getEncryptor()

                val authPrompt = Class3BiometricAuthPrompt.Builder("Strong biometry", "dismiss").apply {
                    setSubtitle("Input your biometry")
                    setDescription("We need your finger")
                    setConfirmationRequired(true)
                }.build()

                lifecycleScope.launch {
                    try {
                        val authResult = authPrompt.authenticate(AuthPromptHost(this@MainActivity), encryptor)
                        val encryptedEntity = authResult.cryptoObject?.cipher?.let { cipher ->
                            biometricCipher.encrypt("Secret data", cipher)
                        }
                        Log.d(MainActivity::class.simpleName, String(encryptedEntity!!.ciphertext))
                    } catch (e: AuthPromptErrorException) {
                        Log.e("AuthPromptError", e.message ?: "no message")
                    } catch (e: AuthPromptFailureException) {
                        Log.e("AuthPromptFailure", e.message ?: "no message")
                    }
                }
            } else {
                Toast.makeText(this, "Biometry not supported", Toast.LENGTH_LONG).show()
            }
        }


        binding.loginButton.setOnClickListener {
            val email = binding.emailEdit.text.toString()
            val password = binding.passwordEdit.text.toString()

            if (email == "otus@test.com" && password == "otus") {
                val fakeToken = "otus_auth_token_123456"
                preferences.setAuthToken(fakeToken, key)
                binding.tokenText.text = "Token: $fakeToken (saved encrypted)"
                Toast.makeText(this, "Login success! Token saved", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this, "Invalid credentials", Toast.LENGTH_SHORT).show()
            }
        }


        val savedToken = preferences.getAuthToken(key)
        if (!savedToken.isNullOrEmpty()) {
            binding.tokenText.text = "Token: $savedToken (decrypted)"
        }


        binding.biometrySwitch.isChecked = preferences.isBiometryEnabled()
        binding.biometrySwitch.setOnCheckedChangeListener { _, isChecked ->
            preferences.setBiometryEnabled(isChecked)
            Toast.makeText(this, "Biometry login is ${if (isChecked) "enabled" else "disabled"}", Toast.LENGTH_SHORT).show()
        }


        if (preferences.isBiometryEnabled()) {
            val canAuth = BiometricManager.from(this).canAuthenticate(BIOMETRIC_STRONG or BIOMETRIC_WEAK) == BIOMETRIC_SUCCESS
            if (canAuth) {
                val authPrompt = Class3BiometricAuthPrompt.Builder("Biometric login", "Cancel").apply {
                    setSubtitle("Authenticate to access token")
                    setDescription("Biometric login required")
                    setConfirmationRequired(true)
                }.build()
                lifecycleScope.launch {
                    try {
                        authPrompt.authenticate(AuthPromptHost(this@MainActivity), null)

                        val token = preferences.getAuthToken(key)
                        if (!token.isNullOrEmpty()) {
                            binding.tokenText.text = "Token: $token (decrypted)"
                        }
                    } catch (e: Exception) {
                        Toast.makeText(this@MainActivity, "Biometry failed: ${e.message}", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }
    }
}