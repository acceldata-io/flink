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

import org.apache.flink.annotation.Internal;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.security.passwords.resolvers.AesEncryptedPasswordResolver;
import org.apache.flink.security.passwords.resolvers.EnvironmentVariablePasswordResolver;
import org.apache.flink.security.passwords.resolvers.JettyObfuscatedPasswordResolver;
import org.apache.flink.security.passwords.resolvers.PlaintextPasswordResolver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.ServiceLoader;

/**
 * Central manager for password resolution using pluggable resolvers.
 *
 * <p>This manager coordinates multiple {@link PasswordResolver} implementations
 * to provide secure password resolution from various sources and formats.
 *
 * <p>Built-in resolvers include:
 * <ul>
 *   <li>AES Encrypted passwords (ENC:base64-encrypted-value)</li>
 *   <li>Environment variables (ENV:VARIABLE_NAME)</li>
 *   <li>Jetty OBF obfuscated passwords (OBF:obfuscated-value) - for backward compatibility</li>
 *   <li>Plaintext passwords (fallback)</li>
 * </ul>
 *
 * <p>Additional resolvers can be registered via the ServiceLoader mechanism.
 */
@Internal
public class PasswordManager {

    private static final Logger LOG = LoggerFactory.getLogger(PasswordManager.class);

    private final List<PasswordResolver> resolvers;

    public PasswordManager() {
        this.resolvers = new ArrayList<>();
        loadBuiltInResolvers();
        loadExternalResolvers();
        sortResolversByPriority();

        LOG.info("Initialized password manager with {} resolvers: {}",
                resolvers.size(), getResolverNames());
    }

    /**
     * Resolves a password using the available resolvers.
     *
     * @param password the password to resolve
     * @param config the Flink configuration
     * @return the resolved plaintext password
     * @throws PasswordResolutionException if no resolver can handle the password
     */
    public String resolvePassword(String password, Configuration config)
            throws PasswordResolutionException {

        if (password == null || password.isEmpty()) {
            throw new PasswordResolutionException("Password cannot be null or empty");
        }

        for (PasswordResolver resolver : resolvers) {
            if (resolver.canResolve(password)) {
                try {
                    String resolved = resolver.resolve(password, config);
                    LOG.debug("Successfully resolved password using resolver: {}", resolver.getName());
                    return resolved;
                } catch (Exception e) {
                    LOG.warn("Resolver '{}' failed to resolve password: {}",
                            resolver.getName(), e.getMessage());
                    // Continue to next resolver
                }
            }
        }

        throw new PasswordResolutionException(
                "No resolver found that can handle the password format. " +
                "Available resolvers: " + getResolverNames());
    }

    private void loadBuiltInResolvers() {
        // Order matters - more secure resolvers should have higher priority
        resolvers.add(new AesEncryptedPasswordResolver());
        resolvers.add(new EnvironmentVariablePasswordResolver());
        resolvers.add(new JettyObfuscatedPasswordResolver());
        resolvers.add(new PlaintextPasswordResolver()); // Fallback with lowest priority
    }

    private void loadExternalResolvers() {
        ServiceLoader<PasswordResolver> serviceLoader = ServiceLoader.load(PasswordResolver.class);
        for (PasswordResolver resolver : serviceLoader) {
            resolvers.add(resolver);
            LOG.info("Loaded external password resolver: {}", resolver.getName());
        }
    }

    private void sortResolversByPriority() {
        resolvers.sort(Comparator.comparingInt(PasswordResolver::getPriority).reversed());
    }

    private List<String> getResolverNames() {
        return resolvers.stream()
                .map(PasswordResolver::getName)
                .toList();
    }

    /**
     * Gets the list of registered resolvers for testing purposes.
     */
    List<PasswordResolver> getResolvers() {
        return new ArrayList<>(resolvers);
    }
}