# Keycloak Setup for RadosGW OIDC Integration

This guide provides step-by-step instructions for configuring Keycloak as an OIDC provider for RadosGW authentication with `radosgw-assume`.

## Keycloak Configuration

### Create OIDC Client

Create a public client for `radosgw-assume`:

```yaml
Client ID: radosgw-public
Name: RadosGW Public Client
Description: Public client for RadosGW device and browser authentication
Protocol: openid-connect
Valid Redirect URIs: 
  - http://localhost:8080/callback
  - http://localhost:18088/callback
  - io.cyberduck:oauth # For CyberDuck
Web Origins: http://localhost:8080
Access Type: public
Standard Flow: true
Direct Access Grants: false
OAuth 2.0 Device Authorization Grant: true
```

## RadosGW Integration

### Get IDP thumbprints

```bash
bash scripts/get_thumbprints.sh \
     https://keycloak.example.com/realms/myrealm/.well-known/openid-configuration \
     thumbprints_keycloak.txt
```

### Create a list of allowed clients (audience)

You can hind an example here:

```bash
cat scripts/client_ids_keycloak.txt
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
       https://keycloak.example.com/realms/myrealm \
       YOUR-ADMIN-USER_KEY_ID YOUR-ADMIN-USER_ACCESS_KEY \
       client_ids_keycloak.txt \
       thumbprints_keycloak.txt
```

### Create IAM Role

```bash
radosgw-admin role create --role-name=KeycloakExample --path=/examples/ --assume-role-policy-doc='
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "KeycloakRealm",
      "Effect": "Allow",
      "Principal": {
        "Federated": [
          "arn:aws:iam:::oidc-provider/keycloak.example.com/realms/myrealm"
        ]
      },
      "Action": [
        "sts:AssumeRoleWithWebIdentity"
      ],
      "Condition": {
        "StringEquals": {
          "keycloak.example.com/realms/myrealm:aud": [
            "account",
            "radosgw-public"
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
          "AWS": "arn:aws:iam:::role/examples/KeycloakExample"
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
          "AWS": "arn:aws:iam:::role/examples/KeycloakExample"
      },
      "Resource": [
        "arn:aws:s3:::test-bucket/*"
      ]
    }
  ]
}'
```
