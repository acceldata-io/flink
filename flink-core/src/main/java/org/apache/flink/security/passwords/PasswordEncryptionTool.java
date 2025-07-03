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

import org.apache.flink.security.passwords.resolvers.AesEncryptedPasswordResolver;

import java.io.Console;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;

/**
 * Command-line tool for generating encryption keys and encrypting passwords.
 * 
 * <p>This tool helps users securely manage SSL passwords by providing:
 * <ul>
 *   <li>Generation of strong encryption keys</li>
 *   <li>Encryption of passwords using AES-256-GCM</li>
 *   <li>Support for key files and direct key input</li>
 * </ul>
 * 
 * <p>Usage examples:
 * <pre>
 * # Generate a new encryption key
 * password-encryption-tool.sh --generate-key
 * 
 * # Generate key and save to file
 * password-encryption-tool.sh --generate-key --output-file /path/to/key
 * 
 * # Encrypt a password using a key file
 * password-encryption-tool.sh --encrypt --key-file /path/to/key
 * 
 * # Encrypt a password using a key directly
 * password-encryption-tool.sh --encrypt --key "base64-encoded-key"
 * 
 * # Encrypt a specific password (non-interactive)
 * password-encryption-tool.sh --encrypt --password "mypassword" --key-file /path/to/key
 * </pre>
 */
public class PasswordEncryptionTool {

    private static final String USAGE = 
        "Flink Password Encryption Tool\n" +
        "\n" +
        "Usage:\n" +
        "  Generate encryption key:\n" +
        "    password-encryption-tool.sh --generate-key [--output-file <path>]\n" +
        "\n" +
        "  Encrypt password:\n" +
        "    password-encryption-tool.sh --encrypt [--password <password>] \\\n" +
        "                                 (--key-file <path> | --key <base64-key>)\n" +
        "\n" +
        "Options:\n" +
        "  --generate-key        Generate a new AES-256 encryption key\n" +
        "  --encrypt             Encrypt a password\n" +
        "  --password <pwd>      Password to encrypt (if not provided, will prompt)\n" +
        "  --key-file <path>     Path to file containing encryption key\n" +
        "  --key <base64>        Base64-encoded encryption key\n" +
        "  --output-file <path>  Output file for generated key\n" +
        "  --help               Show this help message\n" +
        "\n" +
        "Security Note:\n" +
        "  Keep your encryption key secure! If the key is compromised,\n" +
        "  all encrypted passwords can be decrypted.\n";

    public static void main(String[] args) {
        try {
            if (args.length == 0 || hasArg(args, "--help")) {
                System.out.println(USAGE);
                return;
            }

            if (hasArg(args, "--generate-key")) {
                generateKey(args);
            } else if (hasArg(args, "--encrypt")) {
                encryptPassword(args);
            } else {
                System.err.println("Error: Please specify either --generate-key or --encrypt");
                System.err.println("Use --help for usage information.");
                System.exit(1);
            }
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void generateKey(String[] args) throws Exception {
        String key = AesEncryptedPasswordResolver.generateKey();
        
        String outputFile = getArgValue(args, "--output-file");
        if (outputFile != null) {
            Path path = Paths.get(outputFile);
            Files.write(path, key.getBytes());
            System.out.println("Encryption key saved to: " + outputFile);
            System.out.println("Key: " + key);
        } else {
            System.out.println("Generated encryption key:");
            System.out.println(key);
            System.out.println();
            System.out.println("Save this key securely! You can:");
            System.out.println("1. Save to file: echo '" + key + "' > /path/to/keyfile");
            System.out.println("2. Set in config: security.ssl.encryption.key=" + key);
            System.out.println("3. Set as env var: export FLINK_SSL_ENCRYPTION_KEY=" + key);
        }
    }

    private static void encryptPassword(String[] args) throws Exception {
        // Get the encryption key
        byte[] key = getEncryptionKey(args);
        
        // Get the password to encrypt
        String password = getArgValue(args, "--password");
        if (password == null) {
            Console console = System.console();
            if (console == null) {
                System.err.println("Error: No console available for password input. " +
                                   "Use --password option instead.");
                System.exit(1);
            }
            
            char[] passwordChars = console.readPassword("Enter password to encrypt: ");
            if (passwordChars == null || passwordChars.length == 0) {
                System.err.println("Error: No password provided");
                System.exit(1);
            }
            password = new String(passwordChars);
            // Clear the password from memory
            java.util.Arrays.fill(passwordChars, ' ');
        }
        
        // Encrypt the password
        String encryptedPassword = AesEncryptedPasswordResolver.encrypt(password, key);
        
        System.out.println("Encrypted password:");
        System.out.println(encryptedPassword);
        System.out.println();
        System.out.println("Use this in your Flink configuration:");
        System.out.println("security.ssl.internal.keystore-password: " + encryptedPassword);
        System.out.println("security.ssl.internal.key-password: " + encryptedPassword);
        System.out.println("security.ssl.internal.truststore-password: " + encryptedPassword);
    }

    private static byte[] getEncryptionKey(String[] args) throws Exception {
        String keyFile = getArgValue(args, "--key-file");
        String keyBase64 = getArgValue(args, "--key");
        
        if (keyFile == null && keyBase64 == null) {
            throw new IllegalArgumentException("Either --key-file or --key must be provided");
        }
        
        if (keyFile != null && keyBase64 != null) {
            throw new IllegalArgumentException("Cannot specify both --key-file and --key");
        }
        
        if (keyFile != null) {
            Path path = Paths.get(keyFile);
            if (!Files.exists(path)) {
                throw new IllegalArgumentException("Key file not found: " + keyFile);
            }
            byte[] keyBytes = Files.readAllBytes(path);
            String keyString = new String(keyBytes).trim();
            return Base64.getDecoder().decode(keyString);
        } else {
            return Base64.getDecoder().decode(keyBase64);
        }
    }

    private static boolean hasArg(String[] args, String arg) {
        for (String a : args) {
            if (a.equals(arg)) {
                return true;
            }
        }
        return false;
    }

    private static String getArgValue(String[] args, String arg) {
        for (int i = 0; i < args.length - 1; i++) {
            if (args[i].equals(arg)) {
                return args[i + 1];
            }
        }
        return null;
    }
} 