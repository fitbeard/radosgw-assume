# GitHub Actions OIDC Integration with RadosGW

This guide shows how to configure GitHub Actions OIDC provider for secure RadosGW access in CI/CD pipelines using `radosgw-assume`.

## Overview

GitHub Actions provides OIDC tokens that can be used for secure, keyless authentication to external services. This integration enables:

- **Keyless Authentication** - No long-lived secrets in repositories
- **Fine-Grained Access Control** - Repository and branch-based permissions
- **Secure CI/CD** - Temporary credentials for each workflow run
- **Zero Maintenance** - GitHub manages the OIDC provider infrastructure

## GitHub OIDC Provider Details

### Provider Information

```yaml
Provider URL: https://token.actions.githubusercontent.com
Issuer: https://token.actions.githubusercontent.com
JWKS URI: https://token.actions.githubusercontent.com/.well-known/jwks
```

## RadosGW Integration

### Get IDP thumbprints

```bash
bash scripts/get_thumbprints.sh \
     https://token.actions.githubusercontent.com/.well-known/jwks \
     thumbprints_github.txt
```

### Create a list of allowed clients (audience)

You can hind an example here:

```bash
cat scripts/client_ids_github.txt
```

### Create OIDC provider

Fo next scripts execution at least the "oidc-provider" and "roles" capabilities are required:

```bash
radosgw-admin caps add --uid="YOUR-ADMIN-USER" --caps="oidc-provider=*"
radosgw-admin caps add --uid="YOUR-ADMIN-USER" --caps="roles=*"
```

```bash
python scripts/manage_oidc_provider.py \
       https://storage.example.com \
       https://token.actions.githubusercontent.com \
       YOUR-ADMIN-USER_KEY_ID YOUR-ADMIN-USER_ACCESS_KEY \
       client_ids_github.txt \
       thumbprints_github.txt
```

### Create IAM Role

```bash
radosgw-admin role create --role-name=GitHubExample --path=/examples/ --assume-role-policy-doc='
{
  "Version":"2012-10-17",
  "Statement": [
    {
      "Sid": "GitHubActions",
      "Effect": "Allow",
      "Principal": {
        "Federated": [
          "arn:aws:iam:::oidc-provider/token.actions.githubusercontent.com"
        ]
      },
      "Action": [
        "sts:AssumeRoleWithWebIdentity"
      ],
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": [
            "custom.audience",
            "https://github.com/username"
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
          "AWS": "arn:aws:iam:::role/examples/GitHubExample"
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
          "AWS": "arn:aws:iam:::role/examples/GitHubExample"
      },
      "Resource": [
        "arn:aws:s3:::test-bucket/*"
      ]
    }
  ]
}'
```

## Workflow Example

```yaml
name: Deploy to Storage

on:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  id-token: write
  contents: read

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Debug JWT token
        id: auth-token
        run: |
            export TOKEN=$(curl -sSL -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL")
            echo $TOKEN | jq .value | base64
      - name: Custom audience example
        id: auth-token-custom
        run: |
            export TOKEN=$(curl -sSL -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=custom.audience")
            echo $TOKEN | jq .value | base64
      - name: Upload to S3
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          RADOSGW_ASSUME_RELEASE: "v1.0.0"
          AWS_ENDPOINT_URL: https://storage.example.com
          RADOSGW_ROLE_ARN: "arn:aws:iam:::role/examples/GitHubExample"
          RADOSGW_OIDC_AUTH_TYPE: token
        run: |
          export RADOSGW_OIDC_TOKEN=$(curl -sSL -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL" | jq -r .value)
      
          gh release download "${RADOSGW_ASSUME_RELEASE}" \
            --repo fitbeard/radosgw-assume \
            --pattern "*linux-amd64*"
      
          tar -zxf radosgw-assume-${RADOSGW_ASSUME_RELEASE}-linux-amd64.tar.gz
      
          eval $(./radosgw-assume -e)
          aws s3 sync ./artifacts s3://deployment-bucket/
```
