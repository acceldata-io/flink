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

import java.nio.charset.StandardCharsets;

/**
 * Password resolver that handles Jetty OBF obfuscated passwords.
 *
 * <p>Format: OBF:obfuscated-value
 *
 * <p><strong>Security Note:</strong> OBF obfuscation is NOT encryption and provides minimal
 * security. It is easily reversible and should only be used for backward compatibility. For new
 * deployments, prefer AES encryption (ENC:) or environment variables (ENV:).
 *
 * <p>To generate OBF passwords, you can use the Jetty Password utility or any compatible
 * obfuscation tool.
 *
 * <p>This resolver maintains backward compatibility with existing Flink configurations that use OBF
 * obfuscated passwords.
 */
public class JettyObfuscatedPasswordResolver implements PasswordResolver {

    private static final String PREFIX = "OBF:";

    @Override
    public boolean canResolve(String password) {
        return password != null && password.startsWith(PREFIX);
    }

    @Override
    public String resolve(String password, Configuration config)
            throws PasswordResolutionException {
        try {
            return deobfuscate(password);
        } catch (Exception e) {
            throw new PasswordResolutionException("Failed to deobfuscate OBF password", e);
        }
    }

    @Override
    public int getPriority() {
        return 20; // Low priority - less secure, mainly for backward compatibility
    }

    @Override
    public String getName() {
        return "Jetty OBF Obfuscated Password Resolver";
    }

    /**
     * Deobfuscate a Jetty OBF obfuscated password.
     *
     * <p>This is a simple implementation of the Jetty OBF deobfuscation algorithm without requiring
     * the Jetty dependency. The algorithm is based on the Jetty Password utility source code.
     *
     * @param obfuscated the OBF obfuscated password (with or without OBF: prefix)
     * @return the deobfuscated password
     * @throws IllegalArgumentException if the obfuscated string is invalid
     */
    private static String deobfuscate(String obfuscated) {
        if (obfuscated == null || obfuscated.isEmpty()) {
            throw new IllegalArgumentException("Obfuscated password cannot be null or empty");
        }

        String s = obfuscated;
        if (s.startsWith(PREFIX)) {
            s = s.substring(PREFIX.length());
        }

        if (s.length() % 4 != 0) {
            throw new IllegalArgumentException(
                    "Invalid OBF obfuscated password format - length must be multiple of 4");
        }

        byte[] b = new byte[s.length() / 2];
        int l = 0;

        for (int i = 0; i < s.length(); i += 4) {
            if (s.charAt(i) == 'U') {
                // Unicode character handling
                i++;
                String x = s.substring(i, i + 4);
                int i0 = Integer.parseInt(x, 36);
                byte bx = (byte) (i0 >> 8);
                b[l++] = bx;
            } else {
                // Regular character handling
                String x = s.substring(i, i + 4);
                int i0 = Integer.parseInt(x, 36);
                int i1 = (i0 / 256);
                int i2 = (i0 % 256);
                byte bx = (byte) ((i1 + i2 - 254) / 2);
                b[l++] = bx;
            }
        }

        return new String(b, 0, l, StandardCharsets.UTF_8);
    }
}
