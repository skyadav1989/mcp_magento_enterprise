#!/usr/bin/env python3
"""End-to-End System Verification Script for Magento MCP Enterprise Gateway.

Usage:
    python verify_gateway.py [--base-url http://localhost:8000]

Verifies all critical subsystems:
    1. Health Endpoint & Service Info
    2. OAuth 2.1 Metadata Discovery (Well-Known endpoints)
    3. Secret Cryptography (Fernet Token Encryption/Decryption)
    4. Database Connectivity & Schema
    5. OAuth Authorize & PKCE Parameter Validation
    6. JWT Minting & Cryptographic Verification
    7. Approvals Workflow & RBAC Security Enforcement
    8. MCP Gateway Tool Catalog & Permissions
"""

import sys
import time
import argparse
import secrets
import hashlib
import base64
import jwt
import httpx
from sqlalchemy import select, inspect

from app.config import get_settings
from app.db.database import SessionLocal, engine
from app.db.models import User, MagentoConnection, OAuthAuthorizationCode, AuditEvent
from app.services.crypto import encrypt, decrypt
from app.security import JWTVerifier
from app.approvals import ApprovalStore
from app.rbac import allowed_tools, can_use

# ANSI Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

passed_checks = 0
failed_checks = 0

def check_mark(status: bool) -> str:
    global passed_checks, failed_checks
    if status:
        passed_checks += 1
        return f"{GREEN}[PASS]{RESET}"
    else:
        failed_checks += 1
        return f"{RED}[FAIL]{RESET}"

def log_test(name: str, passed: bool, detail: str = ""):
    print(f"  {check_mark(passed)} {BOLD}{name}{RESET}")
    if detail:
        color = CYAN if passed else RED
        print(f"         {color}-> {detail}{RESET}")

def main():
    parser = argparse.ArgumentParser(description="Verify Magento MCP Gateway")
    parser.add_argument("--base-url", default="http://localhost:8000", help="Base URL of running server")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    settings = get_settings()

    print(f"\n{BOLD}{CYAN}================================================================={RESET}")
    print(f"{BOLD}{CYAN}      Magento MCP Enterprise Gateway - System Verification       {RESET}")
    print(f"{BOLD}{CYAN}================================================================={RESET}")
    print(f"Target Server : {base_url}")
    print(f"Database URL  : {settings.database_url}")
    print(f"Issuer URL    : {settings.oauth_issuer_url}")
    print(f"Resource URL  : {settings.mcp_resource_url}")
    print("-" * 65)

    client = httpx.Client(timeout=10.0)

    # -------------------------------------------------------------
    # 1. Health Endpoint
    # -------------------------------------------------------------
    print(f"\n{BOLD}1. Health & Service Status{RESET}")
    try:
        res = client.get(f"{base_url}/health")
        data = res.json() if res.status_code == 200 else {}
        ok = res.status_code == 200 and data.get("status") == "ok"
        log_test("Health Endpoint (/health)", ok, f"Status: {res.status_code}, App: '{data.get('service')}' v{data.get('version')}")
    except Exception as exc:
        log_test("Health Endpoint (/health)", False, f"Server unreachable: {exc}")

    # -------------------------------------------------------------
    # 2. OAuth 2.1 Metadata Discovery
    # -------------------------------------------------------------
    print(f"\n{BOLD}2. OAuth 2.1 Metadata Discovery{RESET}")
    try:
        res_res = client.get(f"{base_url}/.well-known/oauth-protected-resource")
        res_data = res_res.json() if res_res.status_code == 200 else {}
        ok_res = res_res.status_code == 200 and res_data.get("resource") == settings.mcp_resource_url
        log_test("OAuth Protected Resource Metadata", ok_res, f"Resource: {res_data.get('resource')}")

        res_auth = client.get(f"{base_url}/.well-known/oauth-authorization-server")
        auth_data = res_auth.json() if res_auth.status_code == 200 else {}
        ok_auth = res_auth.status_code == 200 and "authorization_code" in auth_data.get("grant_types_supported", [])
        log_test("OAuth Authorization Server Metadata", ok_auth, f"Issuer: {auth_data.get('issuer')}, PKCE: {auth_data.get('code_challenge_methods_supported')}")
    except Exception as exc:
        log_test("OAuth Metadata Endpoints", False, str(exc))

    # -------------------------------------------------------------
    # 3. Secret-at-Rest Encryption (Fernet)
    # -------------------------------------------------------------
    print(f"\n{BOLD}3. Secret-at-Rest Encryption (Fernet){RESET}")
    try:
        sample_token = "magento-integration-token-live-verification"
        enc = encrypt(sample_token)
        dec = decrypt(enc)
        ok_crypto = enc != sample_token and dec == sample_token
        log_test("Fernet Encryption / Decryption Roundtrip", ok_crypto, f"Ciphertext length: {len(enc)} chars")
    except Exception as exc:
        log_test("Fernet Encryption / Decryption", False, str(exc))

    # -------------------------------------------------------------
    # 4. Database Schema & Persistence
    # -------------------------------------------------------------
    print(f"\n{BOLD}4. Database Connectivity & Models{RESET}")
    try:
        inspector = inspect(engine)
        existing_tables = inspector.get_table_names()
        expected_tables = ["users", "magento_connections", "oauth_authorization_codes", "audit_events"]
        missing = [t for t in expected_tables if t not in existing_tables]
        ok_db = len(missing) == 0
        log_test("Database Tables Existence", ok_db, f"Verified tables: {', '.join(expected_tables)}")

        # Check session query
        with SessionLocal() as db:
            user_count = db.query(User).count()
            conn_count = db.query(MagentoConnection).count()
            log_test("Database Session Query", True, f"Users: {user_count}, Magento Connections: {conn_count}")
    except Exception as exc:
        log_test("Database Verification", False, str(exc))

    # -------------------------------------------------------------
    # 5. OAuth Authorize & PKCE Validation
    # -------------------------------------------------------------
    print(f"\n{BOLD}5. OAuth Authorize & PKCE Validation{RESET}")
    try:
        # Generate PKCE verifier and challenge
        code_verifier = secrets.token_urlsafe(64)
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

        allowed_redirect = settings.oauth_allowed_redirect_uris.split(",")[0].strip()

        # Test GET /oauth/authorize form
        auth_page = client.get(
            f"{base_url}/oauth/authorize",
            params={
                "client_id": "verify_script",
                "redirect_uri": allowed_redirect,
                "response_type": "code",
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "resource": settings.mcp_resource_url,
            },
        )
        ok_form = auth_page.status_code == 200 and "Connect Magento" in auth_page.text
        log_test("OAuth Authorize Page Rendering", ok_form, f"Status: {auth_page.status_code}, Form found: {ok_form}")

        # Test Reject unauthorized redirect URI
        bad_redirect = client.get(
            f"{base_url}/oauth/authorize",
            params={
                "client_id": "verify_script",
                "redirect_uri": "https://unauthorized-domain.com/callback",
                "response_type": "code",
                "code_challenge": code_challenge,
                "resource": settings.mcp_resource_url,
            },
        )
        ok_bad_redirect = bad_redirect.status_code == 400
        log_test("OAuth Redirect URI Security", ok_bad_redirect, f"Correctly rejected unauthorized callback with 400")
    except Exception as exc:
        log_test("OAuth Authorize Checks", False, str(exc))

    # -------------------------------------------------------------
    # 6. JWT Security & Verification
    # -------------------------------------------------------------
    print(f"\n{BOLD}6. JWT Minting & Cryptographic Verification{RESET}")
    try:
        verifier = JWTVerifier()
        secret = settings.oauth_signing_secret or settings.dev_jwt_secret
        now = int(time.time())

        # Mint test admin token
        payload = {
            "iss": settings.oauth_issuer_url.rstrip("/"),
            "sub": "verify_admin_user",
            "aud": settings.mcp_resource_url,
            "tenant_id": "tenant_verify_live",
            "role": "admin",
            "scope": "magento.read magento.write",
            "client_id": "verify_client",
            "iat": now,
            "exp": now + 3600,
        }
        token_str = jwt.encode(payload, secret, algorithm="HS256")

        import asyncio
        verified_token = asyncio.run(verifier.verify_token(token_str))
        ok_jwt = (
            verified_token is not None
            and verified_token.claims.get("role") == "admin"
            and verified_token.claims.get("tenant_id") == "tenant_verify_live"
        )
        log_test("JWT Signature & Claims Validation", ok_jwt, f"Subject: {verified_token.subject if verified_token else 'N/A'}")

        # Invalid token rejection
        bad_token = jwt.encode(payload, "wrong-random-secret-key-that-should-fail", algorithm="HS256")
        bad_verified = asyncio.run(verifier.verify_token(bad_token))
        log_test("JWT Invalid Signature Rejection", bad_verified is None, "Correctly rejected fraudulent signature")
    except Exception as exc:
        log_test("JWT Verification", False, str(exc))

    # -------------------------------------------------------------
    # 7. Approvals Workflow & RBAC Security
    # -------------------------------------------------------------
    print(f"\n{BOLD}7. Approvals Workflow & RBAC Security{RESET}")
    try:
        from app.main import app, approvals
        from starlette.testclient import TestClient

        # 1. ApprovalStore Lifecycle test
        local_store = ApprovalStore()
        params = {"sku": "VERIFY-SKU", "description": "Verification test"}
        appr_local = local_store.create("tenant_verify_live", "verify_agent", "update_product_description", params)
        log_test("ApprovalStore Creation & Retrieval", appr_local.approval_id is not None, f"ID: {appr_local.approval_id}")
        local_store.approve(appr_local.approval_id)
        consumed = local_store.consume(appr_local.approval_id, "tenant_verify_live", "verify_agent", "update_product_description", params)
        log_test("ApprovalStore Approval & Consumption", consumed is True, "Successfully consumed approved action")

        # 2. Remote Server HTTP Endpoint Role Enforcement
        agent_payload = dict(payload, role="support_agent")
        agent_token = jwt.encode(agent_payload, secret, algorithm="HS256")
        res_agent_appr = client.post(
            f"{base_url}/approvals/non-existent-id/approve",
            headers={"Authorization": f"Bearer {agent_token}"},
        )
        log_test("Remote /approvals Role Enforcement (Non-admin 403)", res_agent_appr.status_code == 403, f"Agent status: {res_agent_appr.status_code}")

        res_admin_404 = client.post(
            f"{base_url}/approvals/non-existent-id/approve",
            headers={"Authorization": f"Bearer {token_str}"},
        )
        log_test("Remote /approvals Admin Authentication", res_admin_404.status_code == 404, f"Admin status: {res_admin_404.status_code} (token accepted, approval not found)")

        # 3. In-Process FastAPI Endpoint Execution
        inproc_client = TestClient(app)
        appr = approvals.create(
            tenant_id="tenant_verify_live",
            subject="verify_agent",
            tool="update_product_description",
            params={"sku": "VERIFY-SKU", "description": "Verification test"},
        )
        res_inproc = inproc_client.post(
            f"/approvals/{appr.approval_id}/approve",
            headers={"Authorization": f"Bearer {token_str}"},
        )
        ok_inproc = res_inproc.status_code == 200 and res_inproc.json().get("approved") is True
        log_test("FastAPI Approve Endpoint Execution", ok_inproc, f"Approved ID: {res_inproc.json().get('approval_id')}")
    except Exception as exc:
        log_test("Approvals Workflow", False, str(exc))

    # -------------------------------------------------------------
    # 8. RBAC Tool Access Mapping
    # -------------------------------------------------------------
    print(f"\n{BOLD}8. RBAC Tool Access Control Matrix{RESET}")
    try:
        support_tools = allowed_tools("support_agent")
        admin_tools = allowed_tools("admin")
        cms_tools = allowed_tools("cms_admin")

        ok_rbac = (
            "get_orders_by_status" in support_tools
            and "update_product_description" not in support_tools
            and "update_product_description" in admin_tools
            and "update_product_description" in cms_tools
        )
        log_test("Role Permission Matrix", ok_rbac, f"support_agent: {support_tools}, admin: {admin_tools}")
    except Exception as exc:
        log_test("RBAC Checks", False, str(exc))

    # -------------------------------------------------------------
    # Final Summary
    # -------------------------------------------------------------
    print(f"\n{BOLD}{CYAN}================================================================={RESET}")
    print(f"{BOLD}                        VERIFICATION SUMMARY                     {RESET}")
    print(f"{BOLD}{CYAN}================================================================={RESET}")
    total = passed_checks + failed_checks
    print(f"Total Checks : {total}")
    print(f"Passed       : {GREEN}{passed_checks}{RESET}")
    print(f"Failed       : {RED if failed_checks > 0 else GREEN}{failed_checks}{RESET}")

    if failed_checks == 0:
        print(f"\n{BOLD}{GREEN}>>> ALL VERIFICATION CHECKS PASSED SUCCESSFULLY! EVERYTHING IS WORKING. <<<{RESET}\n")
        return 0
    else:
        print(f"\n{BOLD}{RED}>>> SOME CHECKS FAILED! Please review the errors above. <<<{RESET}\n")
        return 1

if __name__ == "__main__":
    sys.exit(main())
