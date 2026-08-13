# radosgw-assume

A modern CLI tool that enables seamless AWS role assumption for **Ceph RadosGW** (RADOS Gateway) using **OpenID Connect (OIDC)** authentication. This tool bridges the gap between cloud-native OIDC identity providers and Ceph's S3-compatible storage, providing secure, temporary AWS credentials without managing long-lived access keys.

## What is radosgw-assume?

**radosgw-assume** is a specialized authentication tool designed for **Ceph RadosGW environments** that have been configured with OIDC integration. It automates the complex process of:

1. **OIDC Authentication** - Authenticating with your identity provider (Keycloak, GitHub Actions, etc.)
2. **STS Token Exchange** - Converting OIDC tokens to temporary AWS credentials via RadosGW's STS endpoint
3. **Credential Management** - Providing ready-to-use AWS credentials for S3 operations

## Why radosgw-assume?

### The Challenge

Ceph RadosGW supports OIDC for authentication, but the integration workflow is complex:

- Multiple authentication flows (device, browser, token-based)
- PKCE security requirements for device and browser flows
- Complex STS AssumeRoleWithWebIdentity calls
- Credential formatting for AWS SDK compatibility
- Session duration management

### The Solution

**radosgw-assume** abstracts this complexity into a simple, secure CLI tool that:

- ✅ **Supports multiple OIDC flows** - Device flow for CI/CD, browser flow for interactive use
- ✅ **Handles security properly** - PKCE, state validation, secure token storage
- ✅ **Works everywhere** - CI/CD pipelines, developer workstations, shell scripts
- ✅ **Shell integration** - Export credentials, run one command, or start an authenticated shell
- ✅ **Zero long-lived secrets** - All credentials are temporary and auto-expire

## What Does It Do?

### Core Functionality

**radosgw-assume** performs secure credential acquisition through this workflow:

```ini
┌─────────────────┐    ┌─────────────────────┐    ┌──────────────────┐
│   radosgw-      │    │   OIDC Provider     │    │   RadosGW STS    │
│   assume        │    │   (Keycloak/GitHub) │    │   Endpoint       │
└─────────────────┘    └─────────────────────┘    └──────────────────┘
         │                        │                        │
         │ 1. Initiate Auth       │                        │
         ├───────────────────────▶│                        │
         │                        │                        │
         │ 2. Device/Browser      │                        │
         │    Flow                │                        │
         │◀───────────────────────┤                        │
         │                        │                        │
         │ 3. OIDC Token          │                        │
         │◀───────────────────────┤                        │
         │                        │                        │
         │ 4. AssumeRoleWithWebIdentity                    │
         ├────────────────────────────────────────────────▶│
         │                        │                        │
         │ 5. Temporary AWS Credentials                    │
         │◀────────────────────────────────────────────────┤
         │                        │                        │
         │ 6. Export or Run Command                        │
         │                        │                        │
```

### Supported Authentication Flows

1. **Device Flow** (Default)
   - Perfect for headless environments
   - User completes authorization on separate device
   - PKCE-protected device authorization and token polling
   - RFC 8628 compliant

2. **Browser Flow with PKCE**
   - Interactive desktop authentication
   - Secure authorization code flow with PKCE (RFC 7636)
   - Local callback server for token exchange

3. **Token-Based**
   - Perfect for CI/CD pipelines
   - Use pre-existing OIDC tokens
   - Ideal for environments where tokens are externally managed

### Output Format

**radosgw-assume** provides credentials in shell export format:

```bash
export AWS_ACCESS_KEY_ID='AKIAI...'
export AWS_SECRET_ACCESS_KEY='wJalr...'
export AWS_SESSION_TOKEN='AQoD...'
export AWS_PROFILE='myprofile'
export AWS_CREDENTIAL_EXPIRATION='2024-12-11T15:30:00Z'
export AWS_SESSION_EXPIRATION='2024-12-11T15:30:00Z'
```

## Installation

### Homebrew (macOS/Linux)

```bash
brew install fitbeard/radosgw-assume/radosgw-assume
```

### Binary Download

Download the latest release from [GitHub Releases](https://github.com/fitbeard/radosgw-assume/releases) and extract to your PATH.

## Quick Start

### Basic Usage

```bash
radosgw-assume -h
Usage: radosgw-assume [OPTIONS]
       radosgw-assume exec [OPTIONS] -- COMMAND [ARG...]
       radosgw-assume shell [OPTIONS]
       radosgw-assume (interactive profile selection)

Options:
  -h, --help                Show this help message and exit
  -e, --env                 Use environment variables for configuration
  -p, --profile PROFILE     Use a specific profile from ~/.aws/config
  -v, --verbose             Show verbose output with detailed information
  -d, --duration DURATION   Session duration (default: 1h, min: 15m, max: 12h)
                            Formats: '3600' (seconds), '60m' (minutes), '1h' (hours)
  -s, --session NAME        Session name (default: radosgw-assume-TIMESTAMP)
                            Only alphanumeric characters and dashes allowed
      --no-prompt           Keep the original prompt in an authenticated shell

Commands:
  exec                      Run a command with temporary credentials
  shell                     Start an interactive shell with temporary credentials
  version                   Show version information

Examples:
  radosgw-assume                                # Interactive selection, clean output
  radosgw-assume -p myprofile                   # Use specific profile, clean output
  radosgw-assume --env                          # Use environment variables
  radosgw-assume -d 2h -p myprofile             # 2-hour session duration
  radosgw-assume -d 30m -p myprofile            # 30-minute session duration
  radosgw-assume -d 15m -p myprofile            # 15-minute session duration (minimum)
  radosgw-assume -s my-session -p myprofile     # Custom session name
  radosgw-assume exec -- aws s3 ls              # Select profile, then run once
  radosgw-assume exec -p myprofile -- aws s3 ls # Use specific profile, then run once
  radosgw-assume shell                          # Select profile, then start a shell
  radosgw-assume shell -p myprofile             # Start a shell for a specific profile
  eval $(radosgw-assume)                        # Interactive with credential export
  eval $(radosgw-assume -p myprofile)           # Direct profile with export
  radosgw-assume --verbose                      # Verbose output with detailed info

Environment Variables (when using -e/--env):
  RADOSGW_OIDC_PROVIDER      - OIDC issuer URL (required, except for token auth)
  RADOSGW_OIDC_CLIENT_ID     - OIDC client ID (required, except for token auth)
  AWS_ENDPOINT_URL           - RadosGW endpoint URL (required)
  RADOSGW_ROLE_ARN           - Role ARN to assume (required)
  RADOSGW_ROLE_SESSION_NAME  - Role session name (optional, default: radosgw-assume-TIMESTAMP)
  RADOSGW_OIDC_AUTH_TYPE     - Auth type: device|browser|token (optional, default: device)
  RADOSGW_OIDC_TOKEN         - Pre-existing OIDC token (required for token auth type)
  RADOSGW_OIDC_SCOPE         - OIDC scope (optional, default: openid, ignored for token auth)
  RADOSGW_OIDC_PKCE_METHOD   - PKCE method: S256|plain (optional, default: S256)
  RADOSGW_SSL_VERIFY         - SSL verification: true|false (optional, default: true)

Configuration:
  Edit ~/.aws/config with RadosGW and OIDC settings
```

### Run a Command Without `eval`

Use `exec` when credentials are needed for one command only:

```bash
radosgw-assume exec -p myprofile -- aws s3 ls
```

Everything after `--` is executed with temporary AWS credentials and `AWS_ENDPOINT_URL` in its environment. The source OIDC token is not passed to the command. The parent shell is unchanged, and the command receives the terminal directly with its original exit status and signal behavior. Omit `-p` to select a profile interactively, or use environment configuration:

```bash
radosgw-assume exec -- aws s3 ls
radosgw-assume exec --env -- aws s3 ls
```

### Start an Authenticated Shell

Use `shell` when several interactive commands need the same temporary credentials:

```bash
radosgw-assume shell -p myprofile
```

The command starts an interactive instance of `$SHELL` (or `/bin/sh` when `$SHELL` is unset) and leaves the parent shell unchanged. Type `exit` or press Ctrl+D to return. Bash, Zsh, POSIX SH, Ksh, and Fish prompts are marked with the active profile; Powerlevel10k receives a native prompt segment. Existing shell configuration and themes are loaded normally and are never modified on disk. Use `--no-prompt` to retain the original prompt.

The inner shell receives the same temporary AWS environment as `exec`, plus `RADOSGW_ASSUME_SHELL=1`, `RADOSGW_ASSUME_PROFILE`, and `RADOSGW_ASSUME_PROMPT_LABEL` so prompts and scripts can identify it. The source OIDC token is not passed to the shell. Omit `-p` to select a profile interactively, or use `--env` for environment configuration.

## Key Features

### 🔐 **Security First**

- No long-lived credentials stored
- PKCE for device and browser flows
- Secure token handling
- Automatic credential expiration

### 🚀 **Developer Experience**

- CI/CD pipeline friendly
- Zero-configuration for common setups
- Shell integration for immediate use
- Verbose mode for debugging
- Clean shell export format

### 🔧 **Flexibility**

- Standards-based provider support through OIDC Discovery
- Multiple authentication flows
- Configurable session durations
- Environment variable override

## Who Should Use This?

### Development Teams

- **Ceph RadosGW users** who need temporary S3 credentials
- **Cloud developers** working with OIDC-integrated storage
- **DevOps engineers** building secure CI/CD pipelines

### Use Cases

- **Application Development** - Secure S3 access without embedded credentials
- **Backup Solutions** - Secure backup storage with time-limited access
- **CI/CD Automation** - Pipeline access to artifact storage
- **Developer Workstations** - Personal development environment setup

## Configuration

### AWS Config File

Add RadosGW profiles to your `~/.aws/config`:

```ini
[profile base]
radosgw_oidc_provider    = https://keycloak.example.com/realms/myrealm
radosgw_oidc_client_id   = rgw-client-public
radosgw_oidc_auth_type   = device
radosgw_oidc_scope       = openid offline_access
radosgw_oidc_pkce_method = S256
radosgw_ssl_verify       = false

[profile assume-device]
source_profile    = base
endpoint_url      = https://storage.example.com
role_arn          = arn:aws:iam:::role/examples/KeycloakExample
role_session_name = device-session

[profile assume-browser]
source_profile         = base
endpoint_url           = https://storage.example.com
radosgw_oidc_client_id = rgw-client-public-browser
role_arn               = arn:aws:iam:::role/examples/KeycloakExample
radosgw_oidc_auth_type = browser
radosgw_oidc_scope     = openid

[profile full]
endpoint_url             = https://storage.example.com
radosgw_oidc_provider    = https://keycloak.example.com/realms/myrealm
radosgw_oidc_client_id   = rgw-client-public
radosgw_oidc_auth_type   = device
radosgw_oidc_pkce_method = S256
radosgw_ssl_verify       = false
role_arn                 = arn:aws:iam:::role/examples/KeycloakExample
role_session_name        = my-custom-session
```

`radosgw_oidc_provider` is the provider's issuer URL, not an authorization or token endpoint. For browser and device authentication, `radosgw-assume` loads `${issuer}/.well-known/openid-configuration`, verifies that the returned issuer matches, and uses the advertised endpoints. Browser authentication requires `authorization_endpoint` and `token_endpoint`; device authentication additionally requires `device_authorization_endpoint`. Token-based authentication does not perform discovery.

## RadosGW and OIDC Provider Setup

- **[RadosGW STS Configuration](docs/radosgw-setup.md)** - How to configure RadosGW for OIDC authentication
- **[Keycloak](docs/keycloak-setup.md)** - Keycloak configuration
- **[GitHub Actions](docs/github-actions.md)** - Using GitHub's OIDC provider
- **[Kubernetes](docs/kubernetes-setup.md)** - Kubernetes configuration

### Environment Variables

For configuration-free operation:

```bash
export AWS_ENDPOINT_URL="https://storage.example.com"
export RADOSGW_OIDC_PROVIDER="https://keycloak.example.com/realms/myrealm"
export RADOSGW_OIDC_CLIENT_ID="rgw-client-public"
export RADOSGW_ROLE_ARN="arn:aws:iam:::role/examples/KeycloakExample"
export RADOSGW_ROLE_SESSION_NAME="my-session" # Optional
export RADOSGW_OIDC_AUTH_TYPE="device"        # device|browser|token
export RADOSGW_OIDC_SCOPE="openid"            # Optional
export RADOSGW_OIDC_PKCE_METHOD="S256"        # Optional: S256 (default) or plain
export RADOSGW_SSL_VERIFY="true"              # Optional
```

## Examples

### Development Workflow

```bash
# Set up your profile once
cat >> ~/.aws/config << EOF
[profile myproject]
endpoint_url = https://storage.company.com
radosgw_oidc_provider = https://sso.company.com/realms/engineering
radosgw_oidc_client_id = storage-access
role_arn = arn:aws:iam:::role/DeveloperAccess
EOF

radosgw-assume

# Get credentials and start working
aws s3 ls
```

### CI/CD Pipeline

```yaml
# .github/workflows/deploy.yml
- name: Upload to S3
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    RADOSGW_ASSUME_RELEASE: "v1.2.0"
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
