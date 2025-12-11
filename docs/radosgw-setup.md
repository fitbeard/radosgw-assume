# RadosGW OIDC Configuration

This guide covers how to configure Ceph RadosGW for OpenID Connect (OIDC) authentication, enabling secure role-based access using `radosgw-assume`.

## Overview

RadosGW's OIDC integration allows external identity providers to authenticate users and applications, eliminating the need for long-lived access keys. This setup enables:

- **Federated Authentication** - Users authenticate with your existing identity provider
- **Temporary Credentials** - All access uses time-limited STS tokens
- **Role-Based Access** - Fine-grained permissions through IAM roles
- **Zero Shared Secrets** - No access keys to manage or rotate

## Prerequisites

- Ceph RadosGW cluster (Reef 18.2.0+ recommended)
- OIDC Provider (Keycloak, Auth0, GitLab, etc.)
- Administrative access to RadosGW configuration
- SSL certificates for secure communication

## RadosGW Configuration

### 1. STS Settings

Using your management tool add the following to your RadosGW configuration:

```ini
rgw_sts_key = {sts-key}
rgw_s3_auth_use_sts = true
```

### 2. STS Key Generation

Generate a secure STS key for encrypting/decrypting role session tokens:

```bash
# This key must consist of 16 hexadecimal characters
openssl rand -hex 16

# Example output:
# 2c058cfda4af45f1b5340fece2864a1a
```
