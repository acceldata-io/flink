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

import org.apache.flink.annotation.PublicEvolving;
import org.apache.flink.configuration.Configuration;

/**
 * Interface for resolving passwords from various sources and formats.
 * 
 * <p>This interface allows for pluggable password resolution implementations,
 * supporting various security mechanisms like encryption, obfuscation, 
 * external secret management systems, and Key Management Systems (KMS).
 * 
 * <p>Implementations should be stateless and thread-safe.
 */
@PublicEvolving
public interface PasswordResolver {

    /**
     * Checks if this resolver can handle the given password format.
     *
     * @param password the password string to check
     * @return true if this resolver can handle the password format
     */
    boolean canResolve(String password);

    /**
     * Resolves the password from the given input.
     *
     * @param password the password string to resolve
     * @param config the Flink configuration context
     * @return the resolved plaintext password
     * @throws PasswordResolutionException if the password cannot be resolved
     */
    String resolve(String password, Configuration config) throws PasswordResolutionException;

    /**
     * Gets the priority of this resolver. Higher priority resolvers are tried first.
     * 
     * @return the priority (higher values = higher priority)
     */
    default int getPriority() {
        return 0;
    }

    /**
     * Gets a human-readable name for this resolver.
     *
     * @return the resolver name
     */
    String getName();
} 