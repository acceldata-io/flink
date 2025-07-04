/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.flink.security.passwords.resolvers;

import org.apache.flink.configuration.Configuration;
import org.apache.flink.security.passwords.PasswordResolutionException;
import org.apache.flink.security.passwords.PasswordResolver;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Password resolver that handles AES-256-GCM encrypted passwords.
 *
 * <p>Format: ENC:base64-encoded-encrypted-data
 *
 * <p>This resolver provides strong encryption using AES-256-GCM with authentication. The encryption
 * key is derived from a master key file or configuration property.
 *
 * <p>Key sources (in order of precedence):
 *
 * <ol>
 *   <li>security.ssl.encryption.key-file (path to file containing key)
 *   <li>security.ssl.encryption.key (base64-encoded key in config)
 *   <li>FLINK_SSL_ENCRYPTION_KEY environment variable
 * </ol>
 *
 * <p>To generate an encrypted password:
 *
 * <pre>
 * java -cp flink-dist.jar org.apache.flink.security.passwords.PasswordEncryptionTool \
 *   --password "mypassword" --key-file /path/to/key
 * </pre>
 */
public class AesEncryptedPasswordResolver implements PasswordResolver {

    private static final String PREFIX = "ENC:";
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private static final int KEY_LENGTH = 32; // 256 bits

    // Configuration keys for the encryption key
    private static final String KEY_FILE_CONFIG = "security.ssl.encryption.key-file";
    private static final String KEY_CONFIG = "security.ssl.encryption.key";
    private static final String KEY_ENV_VAR = "FLINK_SSL_ENCRYPTION_KEY";

    @Override
    public boolean canResolve(String password) {
        return password != null && password.startsWith(PREFIX);
    }

    @Override
    public String resolve(String password, Configuration config)
            throws PasswordResolutionException {
        try {
            String encryptedData = password.substring(PREFIX.length());
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);

            byte[] key = getEncryptionKey(config);
            return decrypt(encryptedBytes, key);

        } catch (Exception e) {
            throw new PasswordResolutionException("Failed to decrypt AES encrypted password", e);
        }
    }

    @Override
    public int getPriority() {
        return 100; // High priority - most secure option
    }

    @Override
    public String getName() {
        return "AES-256-GCM Encrypted Password Resolver";
    }

    private byte[] getEncryptionKey(Configuration config) throws PasswordResolutionException {
        // Try key file first
        String keyFilePath = config.getString(KEY_FILE_CONFIG, null);
        if (keyFilePath != null) {
            return readKeyFromFile(keyFilePath);
        }

        // Try configuration property
        String keyBase64 = config.getString(KEY_CONFIG, null);
        if (keyBase64 != null) {
            return Base64.getDecoder().decode(keyBase64);
        }

        // Try environment variable
        String envKey = System.getenv(KEY_ENV_VAR);
        if (envKey != null) {
            return Base64.getDecoder().decode(envKey);
        }

        throw new PasswordResolutionException(
                "No encryption key found. Please set one of: "
                        + KEY_FILE_CONFIG
                        + ", "
                        + KEY_CONFIG
                        + ", or "
                        + KEY_ENV_VAR
                        + " environment variable");
    }

    private byte[] readKeyFromFile(String keyFilePath) throws PasswordResolutionException {
        try {
            Path path = Paths.get(keyFilePath);
            if (!Files.exists(path)) {
                throw new PasswordResolutionException(
                        "Encryption key file not found: " + keyFilePath);
            }

            byte[] keyBytes = Files.readAllBytes(path);
            String keyString = new String(keyBytes).trim();
            return Base64.getDecoder().decode(keyString);

        } catch (Exception e) {
            throw new PasswordResolutionException(
                    "Failed to read encryption key from file: " + keyFilePath, e);
        }
    }

    private String decrypt(byte[] encryptedData, byte[] key) throws Exception {
        if (encryptedData.length < GCM_IV_LENGTH + GCM_TAG_LENGTH) {
            throw new IllegalArgumentException("Encrypted data too short");
        }

        // Extract IV and encrypted content
        byte[] iv = new byte[GCM_IV_LENGTH];
        System.arraycopy(encryptedData, 0, iv, 0, GCM_IV_LENGTH);

        byte[] cipherText = new byte[encryptedData.length - GCM_IV_LENGTH];
        System.arraycopy(encryptedData, GCM_IV_LENGTH, cipherText, 0, cipherText.length);

        // Decrypt
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);

        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
        byte[] decryptedBytes = cipher.doFinal(cipherText);

        return new String(decryptedBytes);
    }

    /**
     * Utility method to encrypt a password (used by the password encryption tool).
     *
     * @param password the plaintext password to encrypt
     * @param key the encryption key
     * @return the encrypted password in the format ENC:base64-data
     */
    public static String encrypt(String password, byte[] key) throws Exception {
        // Generate random IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);

        // Encrypt
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);

        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
        byte[] cipherText = cipher.doFinal(password.getBytes());

        // Combine IV + ciphertext
        byte[] result = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(cipherText, 0, result, iv.length, cipherText.length);

        return PREFIX + Base64.getEncoder().encodeToString(result);
    }

    /**
     * Generates a new random encryption key.
     *
     * @return a base64-encoded encryption key
     */
    public static String generateKey() {
        byte[] key = new byte[KEY_LENGTH];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }
}
