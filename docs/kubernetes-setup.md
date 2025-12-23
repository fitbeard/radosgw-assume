# Kubernetes OIDC Integration with RadosGW

This guide demonstrates how to set up Kubernetes Service Account Token Volume Projection for OIDC authentication with RadosGW using `radosgw-assume`. This setup uses KIND (Kubernetes in Docker) for local development and testing.

## Overview

Kubernetes Service Account Token Volume Projection enables pods to authenticate to external services using OIDC tokens. This integration provides:

- **Pod Identity** - Each pod gets a unique, time-limited identity token
- **Fine-Grained Access Control** - Control access based on namespace, service account, and audience
- **Zero Credential Management** - No secrets or keys to manage in pods
- **Secure Workload Identity** - Tokens are automatically rotated and mounted

## Prerequisites

- Docker installed and running
- KIND (Kubernetes in Docker) installed
- kubectl configured
- Administrative access to RadosGW configuration

## Local KIND Cluster Setup

### 1. Create KIND Cluster

Use the provided KIND configuration to create a cluster with proper OIDC settings:

```bash
kind create cluster --config scripts/kind-config.yaml
```

The cluster configuration includes:
- **Custom API Server settings** - Service account issuer and JWKS URI
- **Port mappings** - Kubernetes API accessible on localhost:6443
- **Certificate SANs** - Allows access via localhost and kind.example.com
- **Custom audiences** - Defines valid token audiences

### 2. Apply RBAC Configuration

Apply the RBAC configuration to enable unauthenticated access to OIDC discovery endpoints:

```bash
kubectl apply -f scripts/oidc-rbac.yaml
```

This creates:
- **ClusterRole** - Permissions to access OIDC discovery endpoints

- **ClusterRoleBinding** - Grants unauthenticated users access to discovery

### 3. Verify OIDC Endpoints

Test that the OIDC discovery endpoints are accessible both via kubectl (authenticated) and curl (anonymous):

```bash
# Using kubectl (authenticated access)
kubectl get --raw /.well-known/openid-configuration
kubectl get --raw /openid/v1/jwks

# Using curl (anonymous access) - demonstrates public accessibility
curl -k https://kind.example.com:6443/.well-known/openid-configuration
curl -k https://kind.example.com:6443/openid/v1/jwks

# For local testing, you can also use localhost
curl -k https://localhost:6443/.well-known/openid-configuration
curl -k https://localhost:6443/openid/v1/jwks
```

The anonymous curl access works because of the RBAC configuration that grants `system:unauthenticated` users access to the OIDC discovery endpoints.

## Kubernetes OIDC Provider Details

### Provider Information

The KIND cluster acts as an OIDC provider with the following details:

```yaml
Provider URL: https://kind.example.com:6443
Issuer: https://kind.example.com:6443
JWKS URI: https://kind.example.com:6443/openid/v1/jwks
Audience: 
  - https://kubernetes.default.svc
  - https://kind.example.com:6443
  - custom.audience
```

### Token Claims

Kubernetes service account tokens include standard claims:

```json
{
  "aud": [
    "https://kubernetes.default.svc",
    "https://kind.example.com:6443",
    "custom.audience"
  ],
  "exp": 1798051566,
  "iat": 1766515566,
  "iss": "https://kind.example.com:6443",
  "jti": "48956d44-e317-4c75-aa41-f53483733090",
  "kubernetes.io": {
    "namespace": "default",
    "node": {
      "name": "kind-control-plane",
      "uid": "605374a4-3cba-4e3b-a42e-354aa5fede5c"
    },
    "pod": {
      "name": "debug-pod",
      "uid": "16376601-cc54-4b0c-b5b3-16356351e055"
    },
    "serviceaccount": {
      "name": "default",
      "uid": "ed98edcc-f196-49ae-b081-350ea2d36433"
    },
    "warnafter": 1766519173
  },
  "nbf": 1766515566,
  "sub": "system:serviceaccount:default:default"
}
```

## RadosGW Integration

### Get IDP Thumbprints

The JWKS (JSON Web Key Set) certificates in Kubernetes don't have x5t (X.509 Certificate SHA-1 Thumbprint) or x5c (X.509 Certificate Chain) fields because Kubernetes uses raw public keys for JWT verification, not X.509 certificates. Thumbprints list can't be empty in RadosGW OIDC configuration so we put thumbprint of Kubernetes API endpoint certificate here:

```bash
echo |
openssl s_client -servername kind.bimbam.dev -connect kind.bimbam.dev:6443 2>/dev/null |
openssl x509 -fingerprint -sha1 -noout |
cut -d'=' -f2 |
tr -d ':'

0AD026973D4CCD0EA29EF628E1F4EB61920B0D05
```

Save thumbprint to `thumbprints_kubernetes.txt`

### Trust Kubernetes self-signed certificate authority

Communication will fail because Kubernetes API is using self-signed CA. To solve this problem we need to add CA bundle to trust store. This operation is out of this scope because it depends on Ceph installation method and tools. For Rook, cephadm or package based installations different steps are needed.

Temporary workaround for testing only (NOT Recommended for Production):

```ini
rgw_verify_ssl = false
```

### Create Allowed Audiences

Create a file with allowed client IDs (audiences) for Kubernetes:

```bash
# Create client IDs file
cat > client_ids_kubernetes.txt << EOF
https://kind.example.com:6443
custom.audience
EOF
```

### Create OIDC Provider

For next scripts execution at least the "oidc-provider" and "roles" capabilities are required:

```bash
radosgw-admin caps add --uid="YOUR-ADMIN-USER" --caps="oidc-provider=*"
radosgw-admin caps add --uid="YOUR-ADMIN-USER" --caps="roles=*"
```

```bash
python scripts/manage_oidc_provider.py \
       https://storage.example.com \
       https://kind.example.com:6443 \
       YOUR-ADMIN-USER_KEY_ID YOUR-ADMIN-USER_ACCESS_KEY \
       client_ids_kubernetes.txt \
       thumbprints_kubernetes.txt
```

### Create IAM Role for Kubernetes Workloads

Create an IAM role that Kubernetes pods can assume:

```bash
radosgw-admin role create --role-name=KubernetesExample --path=/examples/ --assume-role-policy-doc='
{
  "Version":"2012-10-17",
  "Statement": [
    {
      "Sid": "KubernetesWorkload",
      "Effect": "Allow",
      "Principal": {
        "Federated": [
          "arn:aws:iam:::oidc-provider/kind.example.com:6443"
        ]
      },
      "Action": [
        "sts:AssumeRoleWithWebIdentity"
      ],
      "Condition": {
        "StringEquals": {
          "kind.example.com:6443:aud": [
            "custom.audience",
            "https://kind.example.com:6443"
          ]
        }
      }
    }
  ]
}'
```

### Create bucket and attach policy

```bash
aws s3api create-bucket --bucket test-bucket

aws s3api put-bucket-policy --bucket test-bucket --policy='
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:ListBucket"
      ],
      "Effect": "Allow",
      "Principal": {
          "AWS": "arn:aws:iam:::role/examples/KubernetesExample"
      },
      "Resource": [
        "arn:aws:s3:::test-bucket"
      ]
    },
    {
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:DeleteObject"
      ],
      "Effect": "Allow",
      "Principal": {
          "AWS": "arn:aws:iam:::role/examples/KubernetesExample"
      },
      "Resource": [
        "arn:aws:s3:::test-bucket/*"
      ]
    }
  ]
}'
```

## Example

In this example, the Hashicorp Vault backup job runs using authentication with Kubernetes to access the Vault, and then the snapshot is sent to S3 backup using authentication with RadosGW STS and `radosgw-assume`. Everything is ephemeral.

```yaml
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: vault-backup-script
  namespace: vault
data:
  vault-backup.sh: |
    #!/bin/bash
    #
    export DATE=`date +%Y-%m-%d-%H-%M-%S`
    export RADOSGW_OIDC_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
    export VAULT_TOKEN=$(vault write -field=token auth/kubernetes/$K8S_CLUSTER/login role=vault-backup jwt=$RADOSGW_OIDC_TOKEN)
    vault operator raft snapshot save /tmp/vaultsnapshot-$DATE.snap
    eval $(radosgw-assume -e)
    aws s3 cp /tmp/vaultsnapshot-$DATE.snap s3://$S3_BUCKET/
    rm /tmp/vaultsnapshot-$DATE.snap
    echo "Completed the backup - " $DATE
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: vault-backup
  namespace: vault
spec:
  concurrencyPolicy: Forbid
  schedule: "0 6 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: vault
          containers:
          - name: vault-backup
            image: registry.example.com/images/tools:1.2.1@sha256:3d8ac580f9a3235c9fdd27cda89717a651e34c9b029ae884d8b3fdbcc7bde2a8
            imagePullPolicy: IfNotPresent
            command: ['bash', 'vault-backup.sh']
            env:
              - name: K8S_CLUSTER
                value: kind
              - name: VAULT_ADDR
                value: https://vault.example.com
              - name: S3_BUCKET
                value: vault-backup
              - name: AWS_ENDPOINT_URL
                value: https://storage.example.com
              - name: RADOSGW_OIDC_AUTH_TYPE
                value: token
              - name: RADOSGW_ROLE_ARN
                value: "arn:aws:iam:::role/examples/KubernetesVaultBackup"
            volumeMounts:
              - name: vault-backup-script
                mountPath: "/vault-backup.sh"
                subPath: "vault-backup.sh"
                readOnly: true
          restartPolicy: OnFailure
          volumes:
            - name: vault-backup-script
              configMap:
                name: vault-backup-script
                items:
                  - key: "vault-backup.sh"
                    path: "vault-backup.sh"
```

In this example, we can use a much stricter role condition allowing only service account `vault` from namespace `vault` to use `KubernetesVaultBackup` role:

```bash
radosgw-admin role create --role-name=KubernetesVaultBackup --path=/examples/ --assume-role-policy-doc='
{
  "Version":"2012-10-17",
  "Statement": [
    {
      "Sid": "VaultBackup",
      "Effect": "Allow",
      "Principal": {
        "Federated": [
          "arn:aws:iam:::oidc-provider/kind.example.com:6443"
        ]
      },
      "Action": [
        "sts:AssumeRoleWithWebIdentity"
      ],
      "Condition": {
        "StringEquals": {
          "kind.example.com:6443:sub": [
            "system:serviceaccount:vault:vault"
          ]
        }
      }
    }
  ]
}'
```
