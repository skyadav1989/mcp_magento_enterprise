#!/usr/bin/env python3
"""Script to approve a pending Magento MCP Gateway approval request.

Usage:
  python approve_request.py --approval-id <ID> --store-url <URL> --client-id <CLIENT_ID>

Example:
  python approve_request.py --approval-id nqHvNom6Dtrc_iYS0SlUG9ZP --store-url https://shopdev.okaya.in --client-id <CLIENT_ID>
"""

import sys
import time
import argparse
import hashlib
import jwt
import httpx

from app.config import get_settings


def tenant_id_for(store_url: str, subject: str) -> str:
    normalized = store_url.rstrip("/").lower()
    digest = hashlib.sha256(f"{subject}:{normalized}".encode()).hexdigest()[:24]
    return f"magento_{digest}"


def approve(base_url: str, approval_id: str, tenant_id: str, signing_secret: str):
    now = int(time.time())
    payload = {
        "iss": base_url.rstrip("/"),
        "sub": "admin",
        "aud": f"{base_url.rstrip('/')}/mcp",
        "tenant_id": tenant_id,
        "role": "admin",
        "scope": "magento.read magento.write",
        "iat": now,
        "exp": now + 3600,
    }
    token = jwt.encode(payload, signing_secret, algorithm="HS256")

    endpoint = f"{base_url.rstrip('/')}/approvals/{approval_id}/approve"
    print(f"Calling: POST {endpoint}")
    print(f"Tenant ID: {tenant_id}")

    try:
        res = httpx.post(endpoint, headers={"Authorization": f"Bearer {token}"}, timeout=15.0)
        print(f"Status Code: {res.status_code}")
        print(f"Response: {res.text}")
        if res.status_code == 200:
            print("\n>>> APPROVAL GRANTED! You can now tell ChatGPT to retry with the approval ID. <<<")
            return 0
        else:
            print(f"\n>>> APPROVAL FAILED (HTTP {res.status_code}) <<<")
            return 1
    except Exception as exc:
        print(f"Request failed: {exc}")
        return 1


def main():
    settings = get_settings()
    parser = argparse.ArgumentParser(description="Approve pending MCP Gateway request")
    parser.add_argument("--url", default="https://mcp-magento-enterprise.onrender.com", help="Gateway URL")
    parser.add_argument("--approval-id", required=True, help="Approval ID from ChatGPT")
    parser.add_argument("--tenant-id", help="Exact tenant ID (if known)")
    parser.add_argument("--store-url", help="Magento Store URL entered during OAuth connect")
    parser.add_argument("--client-id", help="OAuth Client ID used by ChatGPT")
    parser.add_argument(
        "--secret",
        default="iB2MmbbFZwidM8qXaGHMXWRMSqEh7WmqbFevGc3z5ne1ma3SUjTU9SU6mVf-otZz",
        help="OAUTH_SIGNING_SECRET from render.env",
    )

    args = parser.parse_args()

    if args.tenant_id:
        tid = args.tenant_id
    elif args.store_url and args.client_id:
        tid = tenant_id_for(args.store_url, args.client_id)
    else:
        print("ERROR: Provide either --tenant-id OR both --store-url and --client-id")
        return 1

    return approve(args.url, args.approval_id, tid, args.secret)


if __name__ == "__main__":
    sys.exit(main())
