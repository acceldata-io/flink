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

/**
 * Password resolver that retrieves passwords from environment variables.
 * 
 * <p>Format: ENV:VARIABLE_NAME
 * 
 * <p>Example:
 * <pre>
 * security.ssl.internal.keystore-password: ENV:SSL_KEYSTORE_PASSWORD
 * </pre>
 * 
 * <p>This allows passwords to be injected via environment variables, which is
 * useful for containerized deployments and CI/CD pipelines where secrets
 * management is handled externally.
 */
public class EnvironmentVariablePasswordResolver implements PasswordResolver {

    private static final String PREFIX = "ENV:";

    @Override
    public boolean canResolve(String password) {
        return password != null && password.startsWith(PREFIX);
    }

    @Override
    public String resolve(String password, Configuration config) throws PasswordResolutionException {
        String variableName = password.substring(PREFIX.length()).trim();
        
        if (variableName.isEmpty()) {
            throw new PasswordResolutionException("Environment variable name cannot be empty");
        }
        
        String value = System.getenv(variableName);
        if (value == null) {
            throw new PasswordResolutionException(
                "Environment variable '" + variableName + "' is not set");
        }
        
        return value;
    }

    @Override
    public int getPriority() {
        return 80; // High priority - secure option
    }

    @Override
    public String getName() {
        return "Environment Variable Password Resolver";
    }
} 