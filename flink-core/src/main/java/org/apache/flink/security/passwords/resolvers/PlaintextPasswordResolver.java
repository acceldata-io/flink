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
 * Password resolver that handles plaintext passwords.
 *
 * <p>This resolver serves as the fallback for all passwords that don't match
 * any other resolver format. It simply returns the password as-is.
 *
 * <p><strong>Security Warning:</strong> Plaintext passwords are a security risk
 * as they are stored in configuration files without any protection. Consider
 * using encrypted passwords (ENC:) or environment variables (ENV:) instead.
 *
 * <p>This resolver is provided for backward compatibility and should have the
 * lowest priority so it's only used when no other resolver can handle the password.
 */
public class PlaintextPasswordResolver implements PasswordResolver {

    @Override
    public boolean canResolve(String password) {
        // This resolver can handle any password as fallback
        return password != null;
    }

    @Override
    public String resolve(String password, Configuration config) throws PasswordResolutionException {
        if (password == null) {
            throw new PasswordResolutionException("Password cannot be null");
        }
        return password;
    }

    @Override
    public int getPriority() {
        return -100; // Lowest priority - fallback resolver
    }

    @Override
    public String getName() {
        return "Plaintext Password Resolver";
    }
}