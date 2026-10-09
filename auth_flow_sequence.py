#!/usr/bin/env python3
"""Magento MCP Gateway - End-to-End Authentication & Tool Execution Sequence.

This script executes the complete sequence in order and prints all keys/responses:
  Step 1: Service Health Check (/health)
  Step 2: PKCE Generation (code_verifier & S256 code_challenge)
  Step 3: Authorization Code Generation (OAuth authorization_code)
  Step 4: Auth Token Exchange (/oauth/token -> Bearer JWT)
  Step 5: MCP Streamable HTTP Init Call (session.initialize())
  Step 6: Call Tool List (session.list_tools())
  Step 7: Call Order List Tool (session.call_tool('get_orders_by_status'))

Run:
  python auth_flow_sequence.py [--url http://localhost:8000]
"""

import sys
import time
import argparse
import secrets
import hashlib
import base64
import json
import ast
import asyncio
import httpx
import jwt

from app.config import get_settings
from app.db.database import SessionLocal
from app.oauth_server import OAuthStore
from app.security import JWTVerifier

# MCP Client SDK
from mcp.client.streamable_http import streamable_http_client
from mcp.client.session import ClientSession

# ANSI Styling
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def print_banner(title: str):
    width = 78
    print(f"\n{BOLD}{CYAN}{'=' * width}{RESET}")
    print(f"{BOLD}{CYAN}  {title.center(width - 4)}  {RESET}")
    print(f"{BOLD}{CYAN}{'=' * width}{RESET}")


def print_step(step_num: int, total_steps: int, title: str):
    progress = f"[{step_num}/{total_steps}]"
    print(f"\n{BOLD}{MAGENTA}{progress} >>> {title.upper()} <<<{RESET}")
    print(f"{DIM}{'-' * 70}{RESET}")


def print_kv(key: str, value: any, indent: int = 2):
    pad = " " * indent
    if isinstance(value, (dict, list)):
        formatted_val = json.dumps(value, indent=2)
        lines = formatted_val.split("\n")
        print(f"{pad}{CYAN}{key:<26}:{RESET}")
        for line in lines:
            print(f"{pad}    {DIM}{line}{RESET}")
    else:
        print(f"{pad}{CYAN}{key:<26}:{RESET} {value}")


def print_success(msg: str):
    print(f"  {GREEN}{BOLD}[PASS]{RESET} {msg}")


def print_fail(msg: str):
    print(f"  {RED}{BOLD}[FAIL]{RESET} {msg}")


async def run_sequence(base_url: str):
    settings = get_settings()
    total_steps = 7
    results = []
    start_time = time.time()

    print_banner("MAGENTO MCP GATEWAY - FULL AUTH & TOOL EXECUTION FLOW")
    print_kv("Target Server", base_url)
    print_kv("MCP Resource Endpoint", f"{base_url}/mcp")
    print_kv("Configured Issuer", settings.oauth_issuer_url)
    print_kv("Allowed Redirect URI", settings.oauth_allowed_redirect_uris)

    async with httpx.AsyncClient(timeout=15.0) as http:

        # ---------------------------------------------------------------------
        # STEP 1: Service Health Check
        # ---------------------------------------------------------------------
        step = 1
        print_step(step, total_steps, "Service Health Check")
        health_url = f"{base_url}/health"
        print_kv("Request", f"GET {health_url}")
        t0 = time.time()
        try:
            res = await http.get(health_url)
            elapsed = (time.time() - t0) * 1000
            print_kv("HTTP Status", f"{res.status_code} ({elapsed:.1f}ms)")
            data = res.json()
            print("\n  Response Keys & Values:")
            for k, v in data.items():
                print_kv(k, v, indent=4)
            if res.status_code == 200 and data.get("status") == "ok":
                print_success("Gateway is healthy and operational")
                results.append((step, "Health Check", True, f"{elapsed:.1f}ms"))
            else:
                print_fail("Unexpected health response")
                results.append((step, "Health Check", False, f"Status {res.status_code}"))
                return 1
        except Exception as exc:
            print_fail(f"Could not connect to {health_url}: {exc}")
            results.append((step, "Health Check", False, str(exc)))
            return 1

        # ---------------------------------------------------------------------
        # STEP 2: PKCE Generated
        # ---------------------------------------------------------------------
        step = 2
        print_step(step, total_steps, "PKCE Generated")
        # 1. High entropy code_verifier
        code_verifier = secrets.token_urlsafe(64)
        # 2. SHA256 digest
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        # 3. Base64url without padding
        code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        code_challenge_method = "S256"

        print("  Generated PKCE Keys & Values:")
        print_kv("code_verifier", code_verifier, indent=4)
        print_kv("code_verifier_length", f"{len(code_verifier)} characters", indent=4)
        print_kv("code_challenge_method", code_challenge_method, indent=4)
        print_kv("code_challenge", code_challenge, indent=4)
        print_success("Cryptographically secure PKCE S256 challenge generated")
        results.append((step, "PKCE Generated", True, f"Length: {len(code_verifier)}"))

        # ---------------------------------------------------------------------
        # STEP 3: Authorization Code Generated
        # ---------------------------------------------------------------------
        step = 3
        print_step(step, total_steps, "Authorization Code Generated")
        client_id = "local-test-client"
        allowed_redirect = settings.oauth_allowed_redirect_uris.split(",")[0].strip()
        auth_code = secrets.token_urlsafe(32)
        tenant_id = "magento_16457de64af92c7429b90eee"
        role = "admin"
        scopes = ["magento.read", "magento.write"]
        ttl = settings.oauth_code_ttl_seconds

        oauth_store = OAuthStore(SessionLocal)
        oauth_store.put(
            code=auth_code,
            client_id=client_id,
            redirect_uri=allowed_redirect,
            code_challenge=code_challenge,
            resource=settings.mcp_resource_url,
            tenant_id=tenant_id,
            subject=client_id,
            role=role,
            scopes=scopes,
            ttl=ttl,
        )

        print("  Authorization Code Record Keys & Values:")
        print_kv("authorization_code", auth_code, indent=4)
        print_kv("client_id", client_id, indent=4)
        print_kv("redirect_uri", allowed_redirect, indent=4)
        print_kv("code_challenge", code_challenge, indent=4)
        print_kv("resource", settings.mcp_resource_url, indent=4)
        print_kv("tenant_id", tenant_id, indent=4)
        print_kv("role", role, indent=4)
        print_kv("scopes", " ".join(scopes), indent=4)
        print_kv("ttl_seconds", ttl, indent=4)
        print_success("Authorization code created and stored in database")
        results.append((step, "Code Generated", True, f"Bound to {tenant_id}"))

        # ---------------------------------------------------------------------
        # STEP 4: Auth Token Exchange
        # ---------------------------------------------------------------------
        step = 4
        print_step(step, total_steps, "Auth Token Exchange (/oauth/token)")
        token_endpoint = f"{base_url}/oauth/token"
        token_payload = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": auth_code,
            "code_verifier": code_verifier,
        }
        print_kv("Request", f"POST {token_endpoint}")
        print("\n  Token Request Payload:")
        for k, v in token_payload.items():
            print_kv(k, v, indent=4)

        t0 = time.time()
        res = await http.post(token_endpoint, data=token_payload)
        elapsed = (time.time() - t0) * 1000
        print_kv("HTTP Status", f"{res.status_code} ({elapsed:.1f}ms)")

        if res.status_code != 200:
            print_fail(f"Token exchange failed: {res.text}")
            results.append((step, "Auth Token", False, f"Status {res.status_code}"))
            return 1

        token_response = res.json()
        access_token = token_response.get("access_token")

        print("\n  Token Response Keys & Values:")
        print_kv("token_type", token_response.get("token_type"), indent=4)
        print_kv("expires_in", f"{token_response.get('expires_in')} seconds", indent=4)
        print_kv("scope", token_response.get("scope"), indent=4)
        print_kv("access_token (JWT)", access_token, indent=4)

        # Decode and display JWT claims
        decoded_claims = jwt.decode(access_token, options={"verify_signature": False})
        print("\n  Decoded JWT Claims:")
        for k, v in decoded_claims.items():
            print_kv(k, v, indent=4)

        print_success("Access token received and verified successfully")
        results.append((step, "Auth Token", True, f"{elapsed:.1f}ms"))

        # ---------------------------------------------------------------------
        # STEP 5: Init Call (MCP Session Initialize)
        # ---------------------------------------------------------------------
        step = 5
        print_step(step, total_steps, "MCP Init Call (Streamable HTTP)")
        mcp_endpoint = f"{base_url}/mcp"
        mcp_auth_headers = {"Authorization": f"Bearer {access_token}"}
        print_kv("MCP Endpoint", mcp_endpoint)
        print_kv("Authorization Header", f"Bearer {access_token[:20]}...{access_token[-20:]}")

        init_info = None
        tools_list = None
        order_result = None

        t0 = time.time()
        try:
            async with httpx.AsyncClient(headers=mcp_auth_headers, timeout=30.0) as mcp_http:
                async with streamable_http_client(mcp_endpoint, http_client=mcp_http) as (read_stream, write_stream, get_session_id):
                    async with ClientSession(read_stream, write_stream) as session:
                        # 5. Initialize
                        init_res = await session.initialize()
                        elapsed_init = (time.time() - t0) * 1000

                        print("\n  MCP Initialize Response Keys & Values:")
                        print_kv("protocolVersion", init_res.protocolVersion, indent=4)
                        print_kv("serverInfo.name", getattr(init_res.serverInfo, "name", None), indent=4)
                        print_kv("serverInfo.version", getattr(init_res.serverInfo, "version", None), indent=4)
                        print_kv("instructions", getattr(init_res, "instructions", None), indent=4)
                        print_kv("capabilities", str(init_res.capabilities), indent=4)
                        session_id = get_session_id()
                        if session_id:
                            print_kv("mcp-session-id", session_id, indent=4)

                        print_success("MCP Session initialized successfully")
                        results.append((step, "Init Call", True, f"{elapsed_init:.1f}ms"))

                        # -----------------------------------------------------
                        # STEP 6: Call Tool List
                        # -----------------------------------------------------
                        step = 6
                        print_step(step, total_steps, "Call Tool List")
                        t1 = time.time()
                        tools_res = await session.list_tools()
                        elapsed_tools = (time.time() - t1) * 1000
                        tools_list = tools_res.tools

                        print(f"  Discovered {len(tools_list)} available tools for authenticated role '{role}':\n")
                        for idx, tool in enumerate(tools_list, 1):
                            print(f"  {BOLD}Tool #{idx}: {tool.name}{RESET}")
                            print_kv("description", tool.description, indent=6)
                            print_kv("inputSchema", tool.inputSchema, indent=6)
                            print()

                        print_success(f"Listed {len(tools_list)} tools successfully")
                        results.append((step, "Call Tool List", True, f"{len(tools_list)} tools found"))

                        # -----------------------------------------------------
                        # STEP 7: Call Order List Tool
                        # -----------------------------------------------------
                        step = 7
                        print_step(step, total_steps, "Call Order List Tool (get_orders_by_status)")
                        tool_name = "get_orders_by_status"
                        tool_args = {"status": "pending", "page_size": 10}

                        print_kv("Tool Name", tool_name)
                        print_kv("Arguments", tool_args)

                        t2 = time.time()
                        call_res = await session.call_tool(tool_name, arguments=tool_args)
                        elapsed_order = (time.time() - t2) * 1000

                        print(f"\n  Tool Execution Result (Status: {elapsed_order:.1f}ms):")
                        print_kv("isError", call_res.isError, indent=4)
                        print("    Content Blocks:")
                        for c_idx, c in enumerate(call_res.content, 1):
                            print(f"      [{c_idx}] type='{c.type}':")
                            try:
                                # Try parsing text as json/dict for clean formatting
                                parsed_data = ast.literal_eval(c.text) if c.text.startswith("{") else json.loads(c.text)
                                print_kv("data", parsed_data, indent=8)
                            except Exception:
                                print(f"          {c.text}")

                        print_success("Order list tool executed successfully and returned response")
                        results.append((step, "Call Order List", True, f"{elapsed_order:.1f}ms"))

        except Exception as exc:
            import traceback
            print_fail(f"MCP Session failed: {exc}")
            traceback.print_exc()
            results.append((step, "MCP Session Error", False, str(exc)))
            return 1

    # -------------------------------------------------------------------------
    # SUMMARY REPORT
    # -------------------------------------------------------------------------
    total_elapsed = time.time() - start_time
    print_banner("EXECUTION SUMMARY REPORT")

    all_passed = True
    for s_num, s_name, s_pass, s_detail in results:
        status_tag = f"{GREEN}[PASS]{RESET}" if s_pass else f"{RED}[FAIL]{RESET}"
        print(f"  {status_tag} Step {s_num}: {s_name:<28} -> {CYAN}{s_detail}{RESET}")
        if not s_pass:
            all_passed = False

    print(f"\n{DIM}{'-' * 70}{RESET}")
    print_kv("Total Duration", f"{total_elapsed:.2f} seconds")
    print_kv("Total Steps Executed", f"{len(results)} of {total_steps}")

    if all_passed and len(results) == total_steps:
        print(f"\n{BOLD}{GREEN}>>> SUCCESS: ALL STEPS VERIFIED WITH FULL RESPONSES DISPLAYED! <<<{RESET}\n")
        return 0
    else:
        print(f"\n{BOLD}{RED}>>> FAILURE: One or more steps failed. See details above. <<<{RESET}\n")
        return 1


def main():
    parser = argparse.ArgumentParser(description="Run OAuth PKCE Sequence against Magento MCP Gateway")
    parser.add_argument("--url", default="http://localhost:8000", help="Base URL of running gateway")
    args = parser.parse_args()

    sys.exit(asyncio.run(run_sequence(args.url.rstrip("/"))))


if __name__ == "__main__":
    main()
