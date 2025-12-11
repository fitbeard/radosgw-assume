#!/usr/bin/env python3

import boto3
import json
import sys
from os.path import exists

def print_usage():
    print("Usage: manage_oidc_provider.py <s3-server> <oidc-url> <iam-client-id> <iam-client-password> <client-ids-file> <thumbprints-file> <ssl-verify>")
    print("\nExample:")
    print("  python3 manage_oidc_provider.py https://storage.example.com https://token.actions.githubusercontent.com IAM_ID IAM_PASS client_ids.txt thumbprints.txt false")
    print("\nDescription:")
    print("  Manages OIDC provider configuration using client IDs and thumbprints from files")
    print("  Supports both reconfiguration and recreation of OIDC providers")
    print("  Files should contain one entry per line")

if len(sys.argv) != 8:
    print_usage()
    sys.exit(1)

# Parse command line arguments
s3_server = sys.argv[1]
oidc_url = sys.argv[2]
iam_client_id = sys.argv[3]
iam_client_password = sys.argv[4]
client_ids_file = sys.argv[5]
thumbprints_file = sys.argv[6]
ssl_verify = sys.argv[7].lower() in ['true', '1', 'yes']

# Validate files exist
for file_path, name in [(client_ids_file, "Client IDs"), (thumbprints_file, "Thumbprints")]:
    if not exists(file_path):
        print(f"Error: {name} file '{file_path}' not found")
        sys.exit(1)

# Read client IDs from file
try:
    with open(client_ids_file, "r") as file:
        client_ids = [line.strip() for line in file if line.strip() and not line.strip().startswith('#')]
    print(f"Loaded {len(client_ids)} client IDs from {client_ids_file}")
except Exception as e:
    print(f"Error reading client IDs file: {e}")
    sys.exit(1)

# Read thumbprints from file
try:
    with open(thumbprints_file, "r") as file:
        thumbprints = [line.strip() for line in file if line.strip() and not line.strip().startswith('#')]
    print(f"Loaded {len(thumbprints)} thumbprints from {thumbprints_file}")
except Exception as e:
    print(f"Error reading thumbprints file: {e}")
    sys.exit(1)

# Configuration summary
print("\n" + "="*60)
print("OIDC PROVIDER MANAGEMENT")
print("="*60)
print(f"\nConfiguration:")
print(f"  S3 Server: {s3_server}")
print(f"  OIDC URL: {oidc_url}")
print(f"  IAM Client ID: {iam_client_id}")
print(f"  Client IDs File: {client_ids_file}")
print(f"  Thumbprints File: {thumbprints_file}")
print(f"  SSL Verify: {ssl_verify}")

print(f"\nClient IDs ({len(client_ids)}):")
for i, client_id in enumerate(client_ids, 1):
    print(f"  {i:2d}. {client_id}")

print(f"\nThumbprints ({len(thumbprints)}):")
for i, thumbprint in enumerate(thumbprints, 1):
    print(f"  {i:2d}. {thumbprint}")

# Create IAM client
print("\n" + "="*60)
print("STEP 1: SETUP IAM CLIENT")
print("="*60)
print(f"Creating IAM client with endpoint: {s3_server}")

try:
    iam_client = boto3.client('iam',
        aws_access_key_id=iam_client_id,
        aws_secret_access_key=iam_client_password,
        endpoint_url=s3_server,
        region_name='',
        verify=ssl_verify
    )
    print("✓ IAM client created successfully")
except Exception as e:
    print(f"✗ Failed to create IAM client: {e}")
    sys.exit(1)

# Check for existing OIDC provider
print("\n" + "="*60)
print("STEP 2: CHECK EXISTING OIDC PROVIDER")
print("="*60)

oidc_provider_path = oidc_url.replace('https://', '').replace('http://', '')
expected_oidc_arn = f"arn:aws:iam:::oidc-provider/{oidc_provider_path}"

existing_provider = None
try:
    oidc_response = iam_client.list_open_id_connect_providers()
    for provider in oidc_response.get('OpenIDConnectProviderList', []):
        if provider['Arn'] == expected_oidc_arn:
            existing_provider = provider
            break
    
    if existing_provider:
        print(f"Found existing OIDC provider: {existing_provider['Arn']}")
        
        # Get detailed info about existing provider
        detail_response = iam_client.get_open_id_connect_provider(
            OpenIDConnectProviderArn=existing_provider['Arn']
        )
        
        current_client_ids = detail_response.get('ClientIDList', [])
        current_thumbprints = detail_response.get('ThumbprintList', [])
        
        print(f"\nCurrent configuration:")
        print(f"  Client IDs ({len(current_client_ids)}):")
        for i, client_id in enumerate(current_client_ids, 1):
            print(f"    {i:2d}. {client_id}")
        print(f"  Thumbprints ({len(current_thumbprints)}):")
        for i, thumbprint in enumerate(current_thumbprints, 1):
            print(f"    {i:2d}. {thumbprint}")
        
        # Check if configuration matches
        client_ids_match = set(current_client_ids) == set(client_ids)
        thumbprints_match = set(current_thumbprints) == set(thumbprints)
        
        if client_ids_match and thumbprints_match:
            print("\n✓ Configuration already matches - no changes needed!")
            sys.exit(0)
        
        print(f"\nConfiguration changes needed:")
        if not client_ids_match:
            print(f"  • Client IDs differ")
            added_clients = set(client_ids) - set(current_client_ids)
            removed_clients = set(current_client_ids) - set(client_ids)
            if added_clients:
                print(f"    + Adding: {', '.join(added_clients)}")
            if removed_clients:
                print(f"    - Removing: {', '.join(removed_clients)}")
        
        if not thumbprints_match:
            print(f"  • Thumbprints differ")
            added_thumbprints = set(thumbprints) - set(current_thumbprints)
            removed_thumbprints = set(current_thumbprints) - set(thumbprints)
            if added_thumbprints:
                print(f"    + Adding: {', '.join(added_thumbprints)}")
            if removed_thumbprints:
                print(f"    - Removing: {', '.join(removed_thumbprints)}")
    else:
        print("No existing OIDC provider found")

except Exception as e:
    print(f"Error checking existing OIDC providers: {e}")

# Ask for confirmation if recreation is needed
if existing_provider:
    print("\n" + "="*60)
    print("STEP 3: CONFIRMATION")
    print("="*60)
    print("OIDC provider update required!")
    print("RadosGW does not support updating OIDC providers - recreation is needed.")
    print("This will temporarily break authentication until recreation is complete.")
    
    while True:
        response = input("\nDo you want to recreate the OIDC provider? [y/N]: ").lower().strip()
        if response in ['n', 'no', '']:
            print("Operation cancelled")
            sys.exit(0)
        elif response in ['y', 'yes']:
            print("Proceeding with recreation...")
            break
        else:
            print("Please enter 'y' for yes or 'n' for no")

# Delete existing OIDC provider if it exists
print("\n" + "="*60)
print("STEP 4: MANAGE OIDC PROVIDER")
print("="*60)

if existing_provider:
    try:
        print(f"Deleting existing OIDC provider: {existing_provider['Arn']}")
        iam_client.delete_open_id_connect_provider(OpenIDConnectProviderArn=existing_provider['Arn'])
        print("✓ Successfully deleted old OIDC provider")
    except Exception as e:
        print(f"Warning: Could not delete OIDC provider: {e}")

# Create new OIDC provider
print(f"\nCreating OIDC provider with URL: {oidc_url}")
print(f"Client IDs to configure ({len(client_ids)}):")
for i, client_id in enumerate(client_ids, 1):
    print(f"  {i:2d}. {client_id}")

print(f"Thumbprints to configure ({len(thumbprints)}):")
for i, thumbprint in enumerate(thumbprints, 1):
    print(f"  {i:2d}. {thumbprint}")

try:
    oidc_response = iam_client.create_open_id_connect_provider(
        Url=oidc_url,
        ClientIDList=client_ids,
        ThumbprintList=thumbprints
    )
    new_oidc_arn = oidc_response['OpenIDConnectProviderArn']
    print(f"\n✓ Successfully created OIDC provider: {new_oidc_arn}")
except Exception as e:
    print(f"✗ Failed to create OIDC provider: {e}")
    sys.exit(1)

# Verification
print("\n" + "="*60)
print("STEP 5: VERIFICATION")
print("="*60)

try:
    verify_response = iam_client.get_open_id_connect_provider(OpenIDConnectProviderArn=new_oidc_arn)
    
    print("✓ OIDC provider verification successful")
    print(f"\nFinal configuration:")
    print(f"  Provider ARN: {new_oidc_arn}")
    print(f"  URL: {verify_response.get('Url')}")
    print(f"  Client IDs ({len(verify_response.get('ClientIDList', []))}):")
    for i, client_id in enumerate(verify_response.get('ClientIDList', []), 1):
        print(f"    {i:2d}. {client_id}")
    print(f"  Thumbprints ({len(verify_response.get('ThumbprintList', []))}):")
    for i, thumbprint in enumerate(verify_response.get('ThumbprintList', []), 1):
        print(f"    {i:2d}. {thumbprint}")
    print(f"  Created: {verify_response.get('CreateDate')}")
    
except Exception as e:
    print(f"Warning: Could not verify OIDC provider: {e}")

print("\n" + "="*60)
print("MANAGEMENT COMPLETE! ✓")
print("="*60)
print(f"\nOIDC provider successfully configured at: {new_oidc_arn}")
print("The provider is ready for use with IAM roles and STS operations.")