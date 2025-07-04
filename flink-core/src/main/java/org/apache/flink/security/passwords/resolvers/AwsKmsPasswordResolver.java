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

import org.apache.flink.annotation.PublicEvolving;
import org.apache.flink.configuration.Configuration;
import org.apache.flink.security.passwords.PasswordResolutionException;
import org.apache.flink.security.passwords.PasswordResolver;

/**
 * Example password resolver that integrates with AWS Key Management Service (KMS).
 *
 * <p>Format: KMS:key-id:encrypted-data
 *
 * <p>Example:
 *
 * <pre>
 * security.ssl.internal.keystore-password: KMS:arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012:AQECAHhEncryptedData...
 * </pre>
 *
 * <p><strong>Note:</strong> This is an example implementation showing how to integrate with
 * external Key Management Systems. To use this resolver:
 *
 * <ol>
 *   <li>Add AWS SDK dependencies to your Flink distribution
 *   <li>Configure AWS credentials (IAM roles, access keys, etc.)
 *   <li>Ensure the Flink process has permissions to decrypt using the specified KMS key
 *   <li>Register this resolver via ServiceLoader or include it in the classpath
 * </ol>
 *
 * <p>This implementation is disabled by default since it requires external dependencies. Enable it
 * by implementing the actual KMS integration and removing the exception in {@link #resolve(String,
 * Configuration)}.
 */
@PublicEvolving
public class AwsKmsPasswordResolver implements PasswordResolver {

    private static final String PREFIX = "KMS:";

    @Override
    public boolean canResolve(String password) {
        return password != null && password.startsWith(PREFIX);
    }

    @Override
    public String resolve(String password, Configuration config)
            throws PasswordResolutionException {
        // This is an example implementation - actual integration would require AWS SDK
        throw new PasswordResolutionException(
                "AWS KMS password resolver is not implemented. "
                        + "This is an example showing how to integrate with external Key Management Systems. "
                        + "To implement:\n"
                        + "1. Add AWS SDK dependencies\n"
                        + "2. Configure AWS credentials\n"
                        + "3. Implement the KMS decryption logic below\n"
                        + "4. Register the resolver via ServiceLoader");

        /*
         * Example implementation (requires AWS SDK):
         *
         * try {
         *     String[] parts = password.substring(PREFIX.length()).split(":", 2);
         *     if (parts.length != 2) {
         *         throw new PasswordResolutionException("Invalid KMS format. Expected: KMS:key-id:encrypted-data");
         *     }
         *
         *     String keyId = parts[0];
         *     String encryptedData = parts[1];
         *
         *     // Initialize AWS KMS client
         *     KmsClient kmsClient = KmsClient.builder()
         *         .region(Region.of(config.getString("aws.region", "us-east-1")))
         *         .build();
         *
         *     // Decrypt the password
         *     DecryptRequest decryptRequest = DecryptRequest.builder()
         *         .keyId(keyId)
         *         .ciphertextBlob(SdkBytes.fromByteArray(Base64.getDecoder().decode(encryptedData)))
         *         .build();
         *
         *     DecryptResponse response = kmsClient.decrypt(decryptRequest);
         *     return response.plaintext().asUtf8String();
         *
         * } catch (Exception e) {
         *     throw new PasswordResolutionException("Failed to decrypt password using AWS KMS", e);
         * }
         */
    }

    @Override
    public int getPriority() {
        return 90; // High priority - enterprise-grade security
    }

    @Override
    public String getName() {
        return "AWS KMS Password Resolver";
    }
}
