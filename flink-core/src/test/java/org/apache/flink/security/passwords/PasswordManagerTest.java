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

package org.apache.flink.security.passwords;

import org.apache.flink.configuration.Configuration;
import org.apache.flink.security.passwords.resolvers.AesEncryptedPasswordResolver;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Tests for the {@link PasswordManager} and related password resolution functionality. */
class PasswordManagerTest {

    @TempDir Path tempDir;

    @Test
    void testPlaintextPasswordResolution() throws Exception {
        PasswordManager manager = new PasswordManager();
        Configuration config = new Configuration();

        String password = "myplaintextpassword";
        String resolved = manager.resolvePassword(password, config);

        assertThat(resolved).isEqualTo(password);
    }

    @Test
    void testObfuscatedPasswordResolution() throws Exception {
        PasswordManager manager = new PasswordManager();
        Configuration config = new Configuration();

        // OBF password for "password"
        String obfPassword = "OBF:1v2j1uum1xtv1zej1zer1xtn1uvk1v1v";
        String resolved = manager.resolvePassword(obfPassword, config);

        assertThat(resolved).isEqualTo("password");
    }

    @Test
    void testEnvironmentVariablePasswordResolution() throws Exception {
        PasswordManager manager = new PasswordManager();
        Configuration config = new Configuration();

        // Set an environment variable (this test assumes JAVA_HOME is set)
        String envPassword = "ENV:JAVA_HOME";
        String resolved = manager.resolvePassword(envPassword, config);

        assertThat(resolved).isEqualTo(System.getenv("JAVA_HOME"));
    }

    @Test
    void testEnvironmentVariableNotFound() {
        PasswordManager manager = new PasswordManager();
        Configuration config = new Configuration();

        String envPassword = "ENV:NONEXISTENT_VAR_12345";

        assertThatThrownBy(() -> manager.resolvePassword(envPassword, config))
                .isInstanceOf(PasswordResolutionException.class)
                .hasMessageContaining("Environment variable 'NONEXISTENT_VAR_12345' is not set");
    }

    @Test
    void testAesEncryptedPasswordResolution() throws Exception {
        PasswordManager manager = new PasswordManager();
        Configuration config = new Configuration();

        // Generate a key and encrypt a password
        String key = AesEncryptedPasswordResolver.generateKey();
        byte[] keyBytes = Base64.getDecoder().decode(key);
        String originalPassword = "mysecretpassword";
        String encryptedPassword = AesEncryptedPasswordResolver.encrypt(originalPassword, keyBytes);

        // Save key to temp file
        Path keyFile = tempDir.resolve("encryption.key");
        Files.write(keyFile, key.getBytes());

        // Configure the key file
        config.setString("security.ssl.encryption.key-file", keyFile.toString());

        // Resolve the password
        String resolved = manager.resolvePassword(encryptedPassword, config);

        assertThat(resolved).isEqualTo(originalPassword);
    }

    @Test
    void testAesEncryptedPasswordWithDirectKey() throws Exception {
        PasswordManager manager = new PasswordManager();
        Configuration config = new Configuration();

        // Generate a key and encrypt a password
        String key = AesEncryptedPasswordResolver.generateKey();
        byte[] keyBytes = Base64.getDecoder().decode(key);
        String originalPassword = "anothersecretpassword";
        String encryptedPassword = AesEncryptedPasswordResolver.encrypt(originalPassword, keyBytes);

        // Configure the key directly
        config.setString("security.ssl.encryption.key", key);

        // Resolve the password
        String resolved = manager.resolvePassword(encryptedPassword, config);

        assertThat(resolved).isEqualTo(originalPassword);
    }

    @Test
    void testNullPassword() {
        PasswordManager manager = new PasswordManager();
        Configuration config = new Configuration();

        assertThatThrownBy(() -> manager.resolvePassword(null, config))
                .isInstanceOf(PasswordResolutionException.class)
                .hasMessageContaining("Password cannot be null or empty");
    }

    @Test
    void testEmptyPassword() {
        PasswordManager manager = new PasswordManager();
        Configuration config = new Configuration();

        assertThatThrownBy(() -> manager.resolvePassword("", config))
                .isInstanceOf(PasswordResolutionException.class)
                .hasMessageContaining("Password cannot be null or empty");
    }

    @Test
    void testResolverPriority() {
        PasswordManager manager = new PasswordManager();

        // Check that resolvers are loaded and sorted by priority
        assertThat(manager.getResolvers()).isNotEmpty();

        // AES should have higher priority than OBF
        boolean foundAes = false;
        boolean foundObf = false;

        for (PasswordResolver resolver : manager.getResolvers()) {
            if (resolver.getName().contains("AES")) {
                foundAes = true;
                assertThat(foundObf).isFalse(); // AES should come before OBF
            } else if (resolver.getName().contains("OBF")) {
                foundObf = true;
            }
        }

        assertThat(foundAes).isTrue();
        assertThat(foundObf).isTrue();
    }
}
