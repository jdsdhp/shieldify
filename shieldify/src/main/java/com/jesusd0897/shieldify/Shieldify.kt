/*
 * Copyright (c) 2020 jesusd0897.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.jesusd0897.shieldify

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.math.BigInteger
import java.nio.charset.Charset
import java.security.*
import java.security.cert.CertificateException
import java.util.*
import javax.crypto.*
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.security.auth.x500.X500Principal

private const val APP_ANDROID_KEY_STORE_NAME = "AndroidKeyStore"

private const val AES_MODE_M_OR_GREATER = "AES/GCM/NoPadding"
private const val AES_MODE_LESS_THAN_M = "AES/ECB/PKCS7Padding"
private const val CHARSET_NAME = "UTF-8"
private const val RSA_ALGORITHM_NAME = "RSA"
private const val RSA_MODE = "RSA/ECB/PKCS1Padding"
private const val CIPHER_PROVIDER_NAME_RSA = "AndroidOpenSSL"
private const val CIPHER_PROVIDER_NAME_AES = "BC"

private const val DEFAULT_PREFERENCE_NAME = "encrypted_room"
private const val DEFAULT_PREFERENCE_KEY = "encrypted_key"

/**
 * @param context App context.
 * @param keyStoreAlias Represent the key inside Android Key Store.
 * It's recommended to use a unique alias for each app separately.
 */
@RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR2)
class Shieldify(
    private val context: Context,
    val keyStoreAlias: String
) {

    private val fixedIV = byteArrayOf(55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44)
    private val keyInitLock = Any()

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR2)
    @Throws(
        KeyStoreException::class,
        CertificateException::class,
        NoSuchAlgorithmException::class,
        IOException::class,
        NoSuchProviderException::class,
        InvalidAlgorithmParameterException::class,
        UnrecoverableEntryException::class,
        NoSuchPaddingException::class,
        InvalidKeyException::class
    )
    private fun initKeys() {
        val keyStore = KeyStore.getInstance(APP_ANDROID_KEY_STORE_NAME)
        keyStore.load(null)
        if (!keyStore.containsAlias(keyStoreAlias)) initValidKeys() else {
            var keyValid = false
            try {
                val keyEntry = keyStore.getEntry(keyStoreAlias, null)
                if (keyEntry is KeyStore.SecretKeyEntry && Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) keyValid =
                    true
                if (keyEntry is KeyStore.PrivateKeyEntry && Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
                    val secretKey = provideSecretKeyFromSharedPreferences()
                    // When doing "Clear data" on Android 4.x it removes the shared preferences (where
                    // we have stored our encrypted secret key) but not the key entry. Check for existence
                    // of key here as well.
                    if (!secretKey.isNullOrBlank()) keyValid = true
                }
            } catch (e: NullPointerException) {
                // Bad to catch null pointer exception, but looks like Android 4.4.x
                // pin switch to password Keystore bug.
                // https://issuetracker.google.com/issues/36983155
                Log.e("TAG", "Failed to get key store entry", e)
            } catch (e: UnrecoverableKeyException) {
                Log.e("TAG", "Failed to get key store entry", e)
            }
            if (!keyValid) {
                synchronized(keyInitLock) { // System upgrade or something made key invalid
                    removeKeys(keyStore)
                    initValidKeys()
                }
            }
        }
    }

    @Throws(KeyStoreException::class)
    private fun removeKeys(keyStore: KeyStore) {
        keyStore.deleteEntry(keyStoreAlias)
        removeSavedSharedPreferences()
    }

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR2)
    @Throws(
        NoSuchAlgorithmException::class,
        NoSuchProviderException::class,
        InvalidAlgorithmParameterException::class,
        CertificateException::class,
        UnrecoverableEntryException::class,
        NoSuchPaddingException::class,
        KeyStoreException::class,
        InvalidKeyException::class,
        IOException::class
    )
    private fun initValidKeys() {
        synchronized(keyInitLock) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) generateKeysForAPIMOrGreater()
            else generateKeysForAPILessThanM()
        }
    }

    private fun removeSavedSharedPreferences() {
        val sharedPreferences =
            context.getSharedPreferences(DEFAULT_PREFERENCE_NAME, Context.MODE_PRIVATE)
        val isCleared = sharedPreferences.edit().clear().commit()
        Log.d("TAG", "Cleared secret key shared preferences $isCleared")
    }

    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR2)
    @Throws(
        NoSuchProviderException::class,
        NoSuchAlgorithmException::class,
        InvalidAlgorithmParameterException::class,
        CertificateException::class,
        UnrecoverableEntryException::class,
        NoSuchPaddingException::class,
        KeyStoreException::class,
        InvalidKeyException::class,
        IOException::class
    )
    private fun generateKeysForAPILessThanM() {
        // Generate a key pair for encryption
        val start = Calendar.getInstance()
        val end = Calendar.getInstance()
        end.add(Calendar.YEAR, 30)
        val spec = KeyPairGeneratorSpec.Builder(context)
            .setAlias(keyStoreAlias)
            .setSubject(X500Principal("CN=$keyStoreAlias"))
            .setSerialNumber(BigInteger.TEN)
            .setStartDate(start.time)
            .setEndDate(end.time)
            .build()
        val kpg = KeyPairGenerator.getInstance(RSA_ALGORITHM_NAME, APP_ANDROID_KEY_STORE_NAME)
        kpg.initialize(spec)
        kpg.generateKeyPair()
        saveEncryptedKey()
    }

    @Throws(
        CertificateException::class,
        NoSuchPaddingException::class,
        InvalidKeyException::class,
        NoSuchAlgorithmException::class,
        KeyStoreException::class,
        NoSuchProviderException::class,
        UnrecoverableEntryException::class,
        IOException::class
    )
    private fun saveEncryptedKey() {
        val pref = context.getSharedPreferences(DEFAULT_PREFERENCE_NAME, Context.MODE_PRIVATE)
        var encryptedKeyBase64encoded = pref.getString(DEFAULT_PREFERENCE_KEY, null)
        if (encryptedKeyBase64encoded == null) {
            val key = ByteArray(16)
            val secureRandom = SecureRandom()
            secureRandom.nextBytes(key)
            val encryptedKey = rsaEncryptKey(key)
            encryptedKeyBase64encoded = Base64.encodeToString(encryptedKey, Base64.DEFAULT)
            val edit = pref.edit()
            edit.putString(DEFAULT_PREFERENCE_KEY, encryptedKeyBase64encoded)
            val successfullyWroteKey = edit.commit()
            if (successfullyWroteKey) {
                Log.d("TAG", "Saved keys successfully")
            } else {
                Log.e("TAG", "Saved keys unsuccessfully")
                throw IOException("Could not save keys")
            }
        }
    }

    @Throws(
        CertificateException::class,
        NoSuchPaddingException::class,
        InvalidKeyException::class,
        NoSuchAlgorithmException::class,
        KeyStoreException::class,
        NoSuchProviderException::class,
        UnrecoverableEntryException::class,
        IOException::class
    )
    private fun provideSecretKeyAPILessThanM(): Key {
        val encryptedKeyBase64Encoded = provideSecretKeyFromSharedPreferences()
        if (encryptedKeyBase64Encoded.isNullOrBlank()) throw InvalidKeyException("Saved key missing from shared preferences")
        val encryptedKey = Base64.decode(encryptedKeyBase64Encoded, Base64.DEFAULT)
        val key = rsaDecryptKey(encryptedKey)
        return SecretKeySpec(key, "AES")
    }

    private fun provideSecretKeyFromSharedPreferences(): String? {
        val preferences =
            context.getSharedPreferences(DEFAULT_PREFERENCE_NAME, Context.MODE_PRIVATE)
        return preferences.getString(DEFAULT_PREFERENCE_KEY, null)
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Throws(
        NoSuchAlgorithmException::class,
        NoSuchProviderException::class,
        InvalidAlgorithmParameterException::class
    )
    private fun generateKeysForAPIMOrGreater() {
        val keyGenerator =
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, APP_ANDROID_KEY_STORE_NAME)
        keyGenerator.init(
            KeyGenParameterSpec.Builder(
                keyStoreAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE) // NOTE no Random IV. According to above this is less secure but acceptably so.
                .setRandomizedEncryptionRequired(false)
                .build()
        )
        // Note according to [docs](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.html)
        // this generation will also add it to the keystore.
        keyGenerator.generateKey()
    }

    @Throws(
        CertificateException::class,
        NoSuchAlgorithmException::class,
        IOException::class,
        KeyStoreException::class,
        UnrecoverableKeyException::class
    )
    private fun provideSecretKeyAPIMorGreater(): Key {
        val keyStore = KeyStore.getInstance(APP_ANDROID_KEY_STORE_NAME)
        keyStore.load(null)
        return keyStore.getKey(keyStoreAlias, null)
    }

    @Throws(
        KeyStoreException::class,
        CertificateException::class,
        NoSuchAlgorithmException::class,
        IOException::class,
        NoSuchProviderException::class,
        NoSuchPaddingException::class,
        UnrecoverableEntryException::class,
        InvalidKeyException::class
    )
    private fun rsaEncryptKey(secret: ByteArray): ByteArray {
        val keyStore = KeyStore.getInstance(APP_ANDROID_KEY_STORE_NAME)
        keyStore.load(null)
        val privateKeyEntry =
            keyStore.getEntry(keyStoreAlias, null) as KeyStore.PrivateKeyEntry
        val inputCipher = Cipher.getInstance(RSA_MODE, CIPHER_PROVIDER_NAME_RSA)
        inputCipher.init(Cipher.ENCRYPT_MODE, privateKeyEntry.certificate.publicKey)
        val outputStream = ByteArrayOutputStream()
        val cipherOutputStream = CipherOutputStream(outputStream, inputCipher)
        cipherOutputStream.write(secret)
        cipherOutputStream.close()
        return outputStream.toByteArray()
    }

    @Throws(
        KeyStoreException::class,
        CertificateException::class,
        NoSuchAlgorithmException::class,
        IOException::class,
        UnrecoverableEntryException::class,
        NoSuchProviderException::class,
        NoSuchPaddingException::class,
        InvalidKeyException::class
    )
    private fun rsaDecryptKey(encrypted: ByteArray): ByteArray {
        val keyStore = KeyStore.getInstance(APP_ANDROID_KEY_STORE_NAME)
        keyStore.load(null)
        val privateKeyEntry =
            keyStore.getEntry(keyStoreAlias, null) as KeyStore.PrivateKeyEntry
        val output = Cipher.getInstance(RSA_MODE, CIPHER_PROVIDER_NAME_RSA)
        output.init(Cipher.DECRYPT_MODE, privateKeyEntry.privateKey)
        val cipherInputStream = CipherInputStream(ByteArrayInputStream(encrypted), output)
        val values = ArrayList<Byte>()
        var nextByte: Int
        while (cipherInputStream.read().also { nextByte = it } != -1) values.add(nextByte.toByte())
        val decryptedKeyAsBytes = ByteArray(values.size)
        for (i in decryptedKeyAsBytes.indices) decryptedKeyAsBytes[i] = values[i]
        return decryptedKeyAsBytes
    }

    @Throws(
        KeyStoreException::class,
        CertificateException::class,
        NoSuchAlgorithmException::class,
        IOException::class
    )
    private fun removeKeys() {
        synchronized(keyInitLock) {
            val keyStore = KeyStore.getInstance(APP_ANDROID_KEY_STORE_NAME)
            keyStore.load(null)
            removeKeys(keyStore)
        }
    }

    /**
     * Encrypt data into Android Key Store.
     * @param stringDataToEncrypt Data to be encrypted.
     */
    @SuppressLint("GetInstance")
    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR2)
    @Throws(
        NoSuchPaddingException::class,
        NoSuchAlgorithmException::class,
        UnrecoverableEntryException::class,
        CertificateException::class,
        KeyStoreException::class,
        IOException::class,
        InvalidAlgorithmParameterException::class,
        InvalidKeyException::class,
        NoSuchProviderException::class,
        BadPaddingException::class,
        IllegalBlockSizeException::class
    )
    fun encryptData(stringDataToEncrypt: String): String {
        initKeys()
        val cipher: Cipher
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            cipher = Cipher.getInstance(AES_MODE_M_OR_GREATER)
            cipher.init(
                Cipher.ENCRYPT_MODE, provideSecretKeyAPIMorGreater(),
                GCMParameterSpec(128, fixedIV)
            )
        } else {
            cipher = Cipher.getInstance(AES_MODE_LESS_THAN_M, CIPHER_PROVIDER_NAME_AES)
            try {
                cipher.init(Cipher.ENCRYPT_MODE, provideSecretKeyAPILessThanM())
            } catch (e: InvalidKeyException) {
                // Since the keys can become bad (perhaps because of lock screen change)
                // drop keys in this case.
                removeKeys()
                throw e
            } catch (e: IOException) {
                removeKeys()
                throw e
            } catch (e: IllegalArgumentException) {
                removeKeys()
                throw e
            }
        }
        val encodedBytes = cipher.doFinal(stringDataToEncrypt.toByteArray(charset(CHARSET_NAME)))
        return Base64.encodeToString(encodedBytes, Base64.DEFAULT)
    }

    /**
     * Decrypt data that comes from Android Key Store.
     * @param providedKey Provided key by encryption operation to recover some data.
     */
    @SuppressLint("GetInstance")
    @RequiresApi(api = Build.VERSION_CODES.JELLY_BEAN_MR2)
    @Throws(
        NoSuchPaddingException::class,
        NoSuchAlgorithmException::class,
        UnrecoverableEntryException::class,
        CertificateException::class,
        KeyStoreException::class,
        IOException::class,
        InvalidAlgorithmParameterException::class,
        InvalidKeyException::class,
        NoSuchProviderException::class,
        BadPaddingException::class,
        IllegalBlockSizeException::class
    )
    fun decryptData(providedKey: String): String {
        initKeys()
        val encryptedDecodedData = Base64.decode(providedKey, Base64.DEFAULT)
        val c: Cipher
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                c = Cipher.getInstance(AES_MODE_M_OR_GREATER)
                c.init(
                    Cipher.DECRYPT_MODE,
                    provideSecretKeyAPIMorGreater(),
                    GCMParameterSpec(128, fixedIV)
                )
            } else {
                c = Cipher.getInstance(AES_MODE_LESS_THAN_M, CIPHER_PROVIDER_NAME_AES)
                c.init(Cipher.DECRYPT_MODE, provideSecretKeyAPILessThanM())
            }
        } catch (e: InvalidKeyException) {
            // Since the keys can become bad (perhaps because of lock screen change)
            // drop keys in this case.
            removeKeys()
            throw e
        } catch (e: IOException) {
            removeKeys()
            throw e
        }
        val decodedBytes = c.doFinal(encryptedDecodedData)
        return String(decodedBytes, Charset.forName(CHARSET_NAME))
    }

}