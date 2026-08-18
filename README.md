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
       radosgw-assume credential-process (-p PROFILE | --env) [OPTIONS]
       radosgw-assume cache <status|clear>
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
      --show-credentials    Allow credential exports to be printed to a terminal
      --no-prompt           Keep the original prompt in an authenticated shell
      --no-cache            Bypass the credential-process cache

Commands:
  exec                      Run a command with temporary credentials
  shell                     Start an interactive shell with temporary credentials
  credential-process        Emit AWS process credential provider JSON
  cache status              Show a non-secret credential cache summary
  cache clear               Remove cached temporary credentials
  version                   Show version information

Examples:
  eval "$(radosgw-assume)"                               # Select and export a profile
  eval "$(radosgw-assume -p myprofile)"                  # Export a specific profile
  eval "$(radosgw-assume --env)"                         # Export environment configuration
  eval "$(radosgw-assume -d 2h -p myprofile)"            # Export a 2-hour session
  eval "$(radosgw-assume -s my-session -p myprofile)"    # Export with a custom session name
  source <(radosgw-assume)                               # Select and export with source
  source <(radosgw-assume -p myprofile)                  # Export a profile with source
  radosgw-assume --show-credentials -p myprofile         # Deliberately display credentials
  radosgw-assume --show-credentials --env                # Display environment-configured credentials
  radosgw-assume exec -- aws s3 ls                       # Select profile, then run once
  radosgw-assume exec -p myprofile -- aws s3 ls          # Use specific profile, then run once
  radosgw-assume shell                                   # Select profile, then start a shell
  radosgw-assume shell -p myprofile                      # Start a shell for a specific profile
  radosgw-assume credential-process -p myprofile         # Emit AWS credential_process JSON
  radosgw-assume credential-process -d 12h -p myprofile  # Request and cache a 12-hour session
  radosgw-assume cache status                            # Inspect cache without exposing credentials
  radosgw-assume cache clear                             # Remove all cached credentials
  eval "$(radosgw-assume --verbose)"                     # Export with detailed diagnostics

Security:
  Credential exports are refused when stdout is a terminal unless --show-credentials is set.
  Capture them with eval/source, or avoid exporting with exec/shell.

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
  RADOSGW_SSL_VERIFY         - SSL verification: true|false|1|0 (optional, default: true)

Configuration:
  Edit ~/.aws/config with RadosGW and OIDC settings
```

### Export Credentials Into the Current Shell

Use either `eval` or `source` to install the generated credential exports in the current shell:

```bash
eval "$(radosgw-assume)"
source <(radosgw-assume)
```

For safety, a direct terminal invocation such as `radosgw-assume -p myprofile` exits before authentication instead of displaying credentials in terminal scrollback. The guard applies only when stdout is a terminal; `eval`, `source`, and explicit redirection continue to receive the generated exports. To deliberately display credentials, opt in explicitly with `radosgw-assume --show-credentials -p myprofile` or `radosgw-assume --show-credentials --env`.

Both forms support interactive profile selection and all regular options. Select a profile directly when interaction is not needed:

```bash
eval "$(radosgw-assume -p myprofile)"
source <(radosgw-assume -p myprofile)
```

The `source <(...)` form uses Zsh process substitution. Bash and Ksh installations may support the same syntax; use the portable `eval` form when they do not.

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

### Use as an AWS Process Credential Provider

The `credential-process` command lets AWS CLI, AWS SDKs, IDEs, and other integrations request RadosGW credentials directly:

```bash
radosgw-assume credential-process -p assume-device
```

It writes the AWS process credential provider JSON document to stdout. When a controlling terminal is available, authentication instructions and progress are written there because AWS tooling can capture process stderr; otherwise they fall back to stderr. The command requires an explicit `-p/--profile` or `--env`; integrations must not depend on an interactive profile selector.

Temporary STS credentials are cached by default in the operating system's user cache directory. Cache directories and files use `0700` and `0600` permissions, writes are atomic, and concurrent requests for the same profile are locked so they do not open multiple authentication flows. Cache entries are isolated by effective profile configuration, requested duration, and token identity for token authentication. The renewal window is 10% of the requested duration, bounded to a minimum of one minute and a maximum of 15 minutes. Use `--no-cache` to bypass both cache reads and writes.

The cache is stored in `~/Library/Caches/radosgw-assume/credentials-v1` on macOS. On Linux it is stored in `$XDG_CACHE_HOME/radosgw-assume/credentials-v1`, or `~/.cache/radosgw-assume/credentials-v1` when `XDG_CACHE_HOME` is unset. The hashed `.json` files contain live temporary credentials and must not be displayed, shared, or committed.

Inspect the cache without displaying profile names, keys, or credentials, or clear all cached temporary credentials:

```bash
radosgw-assume cache status
radosgw-assume cache clear
```

Clearing the cache forces the next `credential-process` request to authenticate again. Expired, malformed, and incomplete entries are removed automatically whenever the credential cache is used. Cache inspection is read-only and reports only entry counts and the cache directory.

Configure a separate AWS consumer profile. Do not add `credential_process` to the RadosGW authentication profile itself: its `role_arn` and `source_profile` keys have different meanings to AWS tooling.

```ini
# Existing RadosGW authentication profile used by radosgw-assume.
[profile assume-device]
source_profile = base
endpoint_url   = https://storage.example.com
role_arn       = arn:aws:iam:::role/examples/KeycloakExample

# Separate profile used by AWS CLI, SDKs, and IDEs.
[profile assume-device-sdk]
credential_process = /absolute/path/to/radosgw-assume credential-process -d 12h -p assume-device
endpoint_url        = https://storage.example.com
```

The `endpoint_url` setting must be repeated in the AWS consumer profile. AWS does not inherit it from the authentication profile, and the process credential JSON format has no endpoint field. Without this setting, AWS CLI may send the temporary RadosGW credentials to an AWS endpoint and report `InvalidAccessKeyId` even though the credentials were issued successfully.

Use an absolute executable path when possible. AWS configuration does not expand `~` or environment variables in `credential_process`. If the path contains spaces, surround the executable path with double quotes.

Test the integration with:

```bash
AWS_PROFILE=assume-device-sdk aws s3 ls
```

AWS credential environment variables take precedence over profiles. If credentials were previously installed with `eval` or `source`, changing `AWS_PROFILE` alone will not activate `credential_process`; stale `AWS_ACCESS_KEY_ID` and `AWS_CREDENTIAL_EXPIRATION` values can instead cause an expired-credentials error. Test from a clean shell or remove the exported credentials for the command:

```bash
env \
  -u AWS_ACCESS_KEY_ID \
  -u AWS_SECRET_ACCESS_KEY \
  -u AWS_SESSION_TOKEN \
  -u AWS_SECURITY_TOKEN \
  -u AWS_CREDENTIAL_EXPIRATION \
  -u AWS_SESSION_EXPIRATION \
  AWS_PROFILE=assume-device-sdk \
  aws s3 ls
```

AWS reruns the command when credentials need refreshing and does not persistently cache external process credentials. Long-running SDK and IDE processes can reuse credentials until refresh, but repeated one-shot AWS CLI invocations may authenticate repeatedly; use `exec` or `shell` for that workflow.

Browser authentication is recommended for GUI IDE integrations because it can open the provider automatically without terminal output. Device authentication works when the calling application has a controlling terminal where the verification URL and code can be displayed.

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

source <(radosgw-assume)

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

    eval "$(./radosgw-assume -e)"
    aws s3 sync ./artifacts s3://deployment-bucket/
```

## Performance Benchmarks

The CLI parser, profile discovery and inheritance, credential-cache key generation and cache-hit path, and session-name validation have network-free benchmarks. Run all of them with allocation reporting:

```bash
go test -run '^$' -bench . -benchmem ./...
```

Benchmark results depend on the host, so compare changes on the same machine and Go version.
