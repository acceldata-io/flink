---
title: "SSL Password Management"
weight: 4
type: docs
aliases:
  - /deployment/security/ssl-setup.html
---
<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->

# SSL Password Management

This document explains how to securely manage SSL passwords in Flink configurations.

## Overview

Flink provides a pluggable password resolution system that supports multiple secure methods for handling SSL passwords, eliminating the need to store plaintext passwords in configuration files.

## Supported Password Formats

### 1. AES-256-GCM Encrypted Passwords (Recommended)

**Format:** `ENC:base64-encoded-encrypted-data`

**Security:** Provides strong encryption using AES-256-GCM with authentication.

**Example Configuration:**
```yaml
security.ssl.internal.keystore-password: ENC:GcmJ5b3BlbnNzbCBhZXMgZW5jcnlwdGVk...
security.ssl.internal.key-password: ENC:YWVzLWVuY3J5cHRlZC1kYXRhLWhlcmU...
security.ssl.internal.truststore-password: ENC:dGhpcyBpcyBhbiBleGFtcGxlIG9mIGFl...
```

**Key Configuration:**
The encryption key can be provided in three ways (in order of precedence):
1. **Key File** (Most secure): `security.ssl.encryption.key-file: /path/to/keyfile`
2. **Configuration Property**: `security.ssl.encryption.key: base64-encoded-key`
3. **Environment Variable**: `FLINK_SSL_ENCRYPTION_KEY=base64-encoded-key`

### 2. Environment Variables

**Format:** `ENV:VARIABLE_NAME`

**Security:** Passwords are injected via environment variables, useful for containerized deployments.

**Example Configuration:**
```yaml
security.ssl.internal.keystore-password: ENV:SSL_KEYSTORE_PASSWORD
security.ssl.internal.key-password: ENV:SSL_KEY_PASSWORD
security.ssl.internal.truststore-password: ENV:SSL_TRUSTSTORE_PASSWORD
```

**Environment Setup:**
```bash
export SSL_KEYSTORE_PASSWORD="your-keystore-password"
export SSL_KEY_PASSWORD="your-key-password"
export SSL_TRUSTSTORE_PASSWORD="your-truststore-password"
```

### 3. Jetty OBF Obfuscated Passwords (Legacy)

**Format:** `OBF:obfuscated-value`

**Security:** ⚠️ **NOT SECURE** - Easily reversible obfuscation. Use only for backward compatibility.

**Example Configuration:**
```yaml
security.ssl.internal.keystore-password: OBF:1v2j1uum1xtv1zej1zer1xtn1uvk1v1v
```

### 4. Plaintext Passwords (Discouraged)

**Format:** Plain text string

**Security:** ⚠️ **NOT SECURE** - Passwords stored in plaintext. Use only for development.

**Example Configuration:**
```yaml
security.ssl.internal.keystore-password: myplaintextpassword
```

## Password Encryption Tool

Flink provides a command-line tool to generate encryption keys and encrypt passwords.

### Generate Encryption Key

```bash
# Generate a new encryption key
./bin/password-encryption-tool.sh --generate-key

# Generate key and save to file
./bin/password-encryption-tool.sh --generate-key --output-file /path/to/keyfile
```

### Encrypt Passwords

```bash
# Encrypt password interactively
./bin/password-encryption-tool.sh --encrypt --key-file /path/to/keyfile

# Encrypt password non-interactively
./bin/password-encryption-tool.sh --encrypt --password "mypassword" --key-file /path/to/keyfile

# Use key directly instead of file
./bin/password-encryption-tool.sh --encrypt --key "base64-encoded-key"
```

## Configuration Examples

### Production Setup with AES Encryption

1. **Generate encryption key:**
```bash
./bin/password-encryption-tool.sh --generate-key --output-file /etc/flink/encryption.key
```

2. **Encrypt your passwords:**
```bash
./bin/password-encryption-tool.sh --encrypt --key-file /etc/flink/encryption.key
# Enter password when prompted
```

3. **Configure Flink:**
```yaml
# SSL Configuration
security.ssl.internal.enabled: true
security.ssl.internal.keystore: /path/to/keystore.jks
security.ssl.internal.keystore-password: ENC:GcmJ5b3BlbnNzbCBhZXMgZW5jcnlwdGVk...
security.ssl.internal.key-password: ENC:YWVzLWVuY3J5cHRlZC1kYXRhLWhlcmU...
security.ssl.internal.truststore: /path/to/truststore.jks
security.ssl.internal.truststore-password: ENC:dGhpcyBpcyBhbiBleGFtcGxlIG9mIGFl...

# Encryption key configuration
security.ssl.encryption.key-file: /etc/flink/encryption.key
```

### Containerized Deployment with Environment Variables

```yaml
# Docker Compose / Kubernetes
environment:
  - SSL_KEYSTORE_PASSWORD=your-keystore-password
  - SSL_KEY_PASSWORD=your-key-password
  - SSL_TRUSTSTORE_PASSWORD=your-truststore-password

# Flink Configuration
security.ssl.internal.enabled: true
security.ssl.internal.keystore: /path/to/keystore.jks
security.ssl.internal.keystore-password: ENV:SSL_KEYSTORE_PASSWORD
security.ssl.internal.key-password: ENV:SSL_KEY_PASSWORD
security.ssl.internal.truststore: /path/to/truststore.jks
security.ssl.internal.truststore-password: ENV:SSL_TRUSTSTORE_PASSWORD
```

## Advanced: Custom Password Resolvers

You can implement custom password resolvers for integration with external systems like HashiCorp Vault, AWS Secrets Manager, or other Key Management Systems.

### Implementing a Custom Resolver

1. **Create a resolver class:**
```java
public class CustomPasswordResolver implements PasswordResolver {
    
    @Override
    public boolean canResolve(String password) {
        return password != null && password.startsWith("CUSTOM:");
    }
    
    @Override
    public String resolve(String password, Configuration config) throws PasswordResolutionException {
        // Your custom resolution logic
        return resolveFromExternalSystem(password);
    }
    
    @Override
    public int getPriority() {
        return 50; // Set appropriate priority
    }
    
    @Override
    public String getName() {
        return "Custom Password Resolver";
    }
}
```

2. **Register via ServiceLoader:**
Create `META-INF/services/org.apache.flink.security.passwords.PasswordResolver` file:
```
com.yourcompany.CustomPasswordResolver
```

## Security Best Practices

1. **Use AES Encryption** for new deployments instead of OBF obfuscation
2. **Protect encryption keys** with appropriate file permissions (`chmod 600`)
3. **Use environment variables** for containerized deployments
4. **Rotate encryption keys** regularly
5. **Monitor access** to configuration files and key files
6. **Use external KMS** for enterprise environments
7. **Avoid plaintext passwords** in production environments

## Migration from OBF to AES

If you're currently using OBF obfuscated passwords, migrate to AES encryption:

1. **Generate new encryption key:**
```bash
./bin/password-encryption-tool.sh --generate-key --output-file /etc/flink/encryption.key
```

2. **Decrypt existing OBF passwords** (if needed) and encrypt with AES:
```bash
# For each OBF password, decrypt it first, then encrypt with AES
./bin/password-encryption-tool.sh --encrypt --key-file /etc/flink/encryption.key
```

3. **Update configuration** to use ENC: format instead of OBF:
```yaml
# Before
security.ssl.internal.keystore-password: OBF:1v2j1uum1xtv1zej1zer1xtn1uvk1v1v

# After
security.ssl.internal.keystore-password: ENC:GcmJ5b3BlbnNzbCBhZXMgZW5jcnlwdGVk...
security.ssl.encryption.key-file: /etc/flink/encryption.key
```

4. **Test thoroughly** before deploying to production

## Troubleshooting

### Common Issues

1. **"No encryption key found"**
   - Ensure `security.ssl.encryption.key-file` points to a valid file
   - Or set `security.ssl.encryption.key` or `FLINK_SSL_ENCRYPTION_KEY` environment variable

2. **"Failed to decrypt AES encrypted password"**
   - Verify the encryption key is correct
   - Check that the encrypted password wasn't corrupted during copy/paste

3. **"Environment variable not set"**
   - Verify the environment variable is set in the process environment
   - Check for typos in variable names

4. **"No resolver found that can handle the password format"**
   - Verify the password format prefix (ENC:, ENV:, OBF:)
   - Check that required resolvers are in the classpath

### Debugging

Enable debug logging for password resolution:
```yaml
log4j.logger.org.apache.flink.security.passwords: DEBUG
```

This will log which resolvers are being tried and any resolution failures. 