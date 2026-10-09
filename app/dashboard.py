"""Admin Approval Web Dashboard for Magento MCP Gateway.

Provides a password-protected web interface at /approvals to inspect pending
human-in-the-loop actions, click Approve, and copy the approval ID for ChatGPT.
"""

import html
import json
import secrets
import time
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from .approvals import ApprovalStore
from .config import get_settings

router = APIRouter(tags=["Approvals Dashboard"])
security = HTTPBasic(auto_error=False)


def verify_dashboard_access(
    request: Request,
    credentials: HTTPBasicCredentials | None = Depends(security),
) -> bool:
    settings = get_settings()
    expected_password = settings.admin_password or settings.oauth_signing_secret or "admin123"

    # 1. Check Query parameter (?key=... or ?password=...)
    q_key = request.query_params.get("key") or request.query_params.get("password")
    if q_key and secrets.compare_digest(q_key, expected_password):
        return True

    # 2. Check Cookie
    cookie_token = request.cookies.get("mcp_admin_token")
    if cookie_token and secrets.compare_digest(cookie_token, expected_password):
        return True

    # 3. Check HTTP Basic Auth header
    if credentials and secrets.compare_digest(credentials.password, expected_password):
        return True

    # Authentication required -> prompt browser basic auth
    raise HTTPException(
        status_code=401,
        detail="Admin authorization required to access approvals",
        headers={"WWW-Authenticate": "Basic realm='Magento MCP Approvals Dashboard'"},
    )


def build_dashboard_html(items, message: str = "", active_id: str = "") -> str:
    settings = get_settings()
    now = time.time()

    cards_html = []
    if not items:
        cards_html.append(
            """
            <div class="empty-state">
                <div class="empty-icon">🛡️</div>
                <h3>No Pending Approval Requests</h3>
                <p>When ChatGPT requests a high-risk action like modifying a product description, it will pause and appear here for human review.</p>
            </div>
            """
        )
    else:
        for item in items:
            remaining_sec = max(0, int(item.expires_at - now))
            mins = remaining_sec // 60
            secs = remaining_sec % 60
            time_str = f"{mins}m {secs}s remaining" if remaining_sec > 0 else "Expired"

            sku = html.escape(str(item.params.get("sku", "N/A")))
            desc = html.escape(str(item.params.get("description", "")))
            appr_id = html.escape(item.approval_id)
            tenant_id = html.escape(item.tenant_id)
            tool_name = html.escape(item.tool)

            status_badge = (
                '<span class="badge approved"><span class="dot"></span>Approved</span>'
                if item.approved
                else f'<span class="badge pending"><span class="dot"></span>Awaiting Approval ({time_str})</span>'
            )

            if item.tool == "add_media_for_sku":
                chatgpt_msg = html.escape(
                    f"The request has been approved. Please retry adding media for SKU {sku} with approval_id: {appr_id}"
                )
                label_val = html.escape(str(item.params.get("label", "Product Image")))
                mime_val = html.escape(str(item.params.get("mime_type", "image/jpeg")))
                file_name_val = html.escape(str(item.params.get("file_name", "N/A")))
                raw_t = item.params.get("types", [])
                types_val = html.escape(", ".join(raw_t) if isinstance(raw_t, list) else str(raw_t))
                b64_val = str(item.params.get("base64_data", ""))

                img_preview = ""
                if b64_val:
                    img_preview = f"""
                    <div style="margin-top: 10px;">
                        <img src="data:{mime_val};base64,{b64_val}" alt="Media Preview" style="max-height: 180px; max-width: 100%; border-radius: 8px; border: 1px solid rgba(255,255,255,0.15); box-shadow: 0 4px 12px rgba(0,0,0,0.3);" />
                    </div>
                    """

                details_html = f"""
                    <div class="meta-row">
                        <span class="meta-label">Image Label:</span>
                        <span class="meta-value">{label_val}</span>
                    </div>
                    <div class="meta-row">
                        <span class="meta-label">File Name:</span>
                        <span class="meta-value"><code>{file_name_val}</code></span>
                    </div>
                    <div class="meta-row">
                        <span class="meta-label">MIME / Roles:</span>
                        <span class="meta-value"><code>{mime_val}</code> ({types_val})</span>
                    </div>
                    <div class="field-block">
                        <span class="meta-label">Image Preview:</span>
                        {img_preview}
                    </div>
                """
            else:
                chatgpt_msg = html.escape(
                    f"The request has been approved. Please retry updating the product description for SKU {sku} with approval_id: {appr_id}"
                )
                details_html = f"""
                    <div class="field-block">
                        <span class="meta-label">New Description to Apply:</span>
                        <div class="desc-box">
                            <pre>{desc}</pre>
                        </div>
                    </div>
                """

            action_ui = ""
            if item.approved:
                action_ui = f"""
                <div class="approved-box">
                    <div class="approved-title">✓ Ready for ChatGPT</div>
                    <p class="approved-desc">Copy this prompt and paste it into ChatGPT to complete the update:</p>
                    <div class="prompt-preview">
                        <code>{chatgpt_msg}</code>
                    </div>
                    <div class="btn-group">
                        <button class="btn btn-copy" onclick="copyText('{chatgpt_msg}', this)">
                            📋 Copy Prompt for ChatGPT
                        </button>
                        <button class="btn btn-secondary" onclick="copyText('{appr_id}', this)">
                            📋 Copy ID Only
                        </button>
                    </div>
                </div>
                """
            else:
                action_ui = f"""
                <div class="action-footer">
                    <form method="POST" action="/approvals/{appr_id}/ui-approve">
                        <button type="submit" class="btn btn-approve">
                            ✓ Approve This Request
                        </button>
                    </form>
                    <button class="btn btn-secondary" onclick="copyText('{appr_id}', this)">
                        📋 Copy Approval ID
                    </button>
                </div>
                """

            card = f"""
            <div class="card {'card-approved' if item.approved else 'card-pending'}" id="card-{appr_id}">
                <div class="card-header">
                    <div class="card-title-group">
                        <span class="tool-tag">{tool_name}</span>
                        {status_badge}
                    </div>
                    <div class="id-badge" onclick="copyText('{appr_id}', this)" title="Click to copy ID">
                        <code>{appr_id}</code>
                        <span class="copy-icon">📋</span>
                    </div>
                </div>

                <div class="card-body">
                    <div class="meta-row">
                        <span class="meta-label">Target SKU:</span>
                        <span class="sku-badge">{sku}</span>
                    </div>
                    <div class="meta-row">
                        <span class="meta-label">Tenant ID:</span>
                        <span class="meta-value"><code>{tenant_id}</code></span>
                    </div>

                    {details_html}
                </div>

                {action_ui}
            </div>
            """
            cards_html.append(card)

    toast_html = ""
    if message:
        toast_html = f"""
        <div class="alert alert-success">
            <span>✓ {html.escape(message)}</span>
            <button onclick="this.parentElement.remove()" class="alert-close">×</button>
        </div>
        """

    return f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{html.escape(settings.app_name)} - Human Approval Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #090d16;
            --surface: #111827;
            --surface-hover: #1f2937;
            --border: #1e293b;
            --border-highlight: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --primary: #6366f1;
            --primary-hover: #4f46e5;
            --success: #10b981;
            --success-glow: rgba(16, 185, 129, 0.2);
            --warning: #f59e0b;
            --warning-glow: rgba(245, 158, 11, 0.2);
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg);
            color: var(--text-primary);
            font-family: 'Inter', -apple-system, sans-serif;
            min-height: 100vh;
            padding: 32px 16px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
        }}
        header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 32px;
            padding-bottom: 24px;
            border-bottom: 1px solid var(--border);
            flex-wrap: wrap;
            gap: 16px;
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .logo-icon {{
            font-size: 28px;
            background: linear-gradient(135deg, #6366f1, #a855f7);
            width: 48px;
            height: 48px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(99, 102, 241, 0.3);
        }}
        h1 {{
            font-size: 22px;
            font-weight: 700;
            color: #fff;
            letter-spacing: -0.02em;
        }}
        .subtitle {{
            font-size: 13px;
            color: var(--text-secondary);
        }}
        .header-actions {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .btn {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 18px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.15s ease;
            border: 1px solid transparent;
            text-decoration: none;
        }}
        .btn-refresh {{
            background: var(--surface);
            color: var(--text-primary);
            border-color: var(--border);
        }}
        .btn-refresh:hover {{
            background: var(--surface-hover);
            border-color: var(--border-highlight);
        }}
        .btn-approve {{
            background: #059669;
            color: white;
            box-shadow: 0 2px 8px rgba(16, 185, 129, 0.3);
        }}
        .btn-approve:hover {{
            background: #10b981;
            box-shadow: 0 4px 14px rgba(16, 185, 129, 0.4);
            transform: translateY(-1px);
        }}
        .btn-copy {{
            background: var(--primary);
            color: white;
            box-shadow: 0 2px 8px rgba(99, 102, 241, 0.3);
        }}
        .btn-copy:hover {{
            background: var(--primary-hover);
        }}
        .btn-secondary {{
            background: rgba(255, 255, 255, 0.05);
            color: var(--text-secondary);
            border-color: var(--border);
        }}
        .btn-secondary:hover {{
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
        }}
        .alert {{
            padding: 14px 18px;
            border-radius: 8px;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 14px;
            font-weight: 500;
            animation: fadeIn 0.2s ease;
        }}
        .alert-success {{
            background: rgba(16, 185, 129, 0.15);
            border: 1px solid rgba(16, 185, 129, 0.4);
            color: #34d399;
        }}
        .alert-close {{
            background: none;
            border: none;
            color: inherit;
            font-size: 18px;
            cursor: pointer;
            padding: 0 4px;
        }}
        .card-list {{
            display: flex;
            flex-direction: column;
            gap: 20px;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 22px;
            transition: all 0.2s ease;
        }}
        .card-pending {{
            border-left: 4px solid var(--warning);
        }}
        .card-approved {{
            border-left: 4px solid var(--success);
            background: linear-gradient(180deg, rgba(16, 185, 129, 0.03) 0%, var(--surface) 100%);
        }}
        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .card-title-group {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .tool-tag {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            font-weight: 600;
            background: rgba(99, 102, 241, 0.15);
            color: #818cf8;
            padding: 4px 10px;
            border-radius: 6px;
            border: 1px solid rgba(99, 102, 241, 0.3);
        }}
        .badge {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            font-size: 12px;
            font-weight: 600;
            padding: 4px 10px;
            border-radius: 20px;
        }}
        .badge.pending {{
            background: rgba(245, 158, 11, 0.12);
            color: #fbbf24;
            border: 1px solid rgba(245, 158, 11, 0.3);
        }}
        .badge.approved {{
            background: rgba(16, 185, 129, 0.12);
            color: #34d399;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }}
        .dot {{
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: currentColor;
        }}
        .id-badge {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: #0f172a;
            border: 1px solid var(--border);
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 12px;
            cursor: pointer;
            transition: all 0.15s;
        }}
        .id-badge:hover {{
            border-color: var(--primary);
            background: rgba(99, 102, 241, 0.1);
        }}
        .id-badge code {{
            font-family: 'JetBrains Mono', monospace;
            color: #cbd5e1;
        }}
        .meta-row {{
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 13px;
            margin-bottom: 8px;
        }}
        .meta-label {{
            color: var(--text-muted);
            font-weight: 500;
        }}
        .meta-value {{
            color: var(--text-secondary);
        }}
        .sku-badge {{
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            color: #f1f5f9;
            background: #1e293b;
            padding: 2px 8px;
            border-radius: 4px;
        }}
        .field-block {{
            margin-top: 14px;
        }}
        .desc-box {{
            background: #0b0f19;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 12px;
            margin-top: 6px;
            max-height: 180px;
            overflow-y: auto;
        }}
        .desc-box pre {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: #e2e8f0;
            white-space: pre-wrap;
            word-break: break-word;
        }}
        .action-footer {{
            margin-top: 20px;
            padding-top: 16px;
            border-top: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }}
        .approved-box {{
            margin-top: 18px;
            padding: 16px;
            background: rgba(16, 185, 129, 0.08);
            border: 1px solid rgba(16, 185, 129, 0.25);
            border-radius: 10px;
        }}
        .approved-title {{
            font-size: 14px;
            font-weight: 700;
            color: #34d399;
            margin-bottom: 4px;
        }}
        .approved-desc {{
            font-size: 12px;
            color: var(--text-secondary);
            margin-bottom: 10px;
        }}
        .prompt-preview {{
            background: #090d16;
            border: 1px solid rgba(16, 185, 129, 0.2);
            padding: 10px 14px;
            border-radius: 6px;
            margin-bottom: 12px;
        }}
        .prompt-preview code {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: #a7f3d0;
            display: block;
            word-break: break-all;
        }}
        .btn-group {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}
        .empty-state {{
            text-align: center;
            padding: 64px 24px;
            background: var(--surface);
            border: 1px dashed var(--border-highlight);
            border-radius: 16px;
        }}
        .empty-icon {{
            font-size: 48px;
            margin-bottom: 16px;
        }}
        .empty-state h3 {{
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 8px;
        }}
        .empty-state p {{
            font-size: 14px;
            color: var(--text-muted);
            max-width: 480px;
            margin: 0 auto;
        }}
        /* Toast notification */
        #toast {{
            position: fixed;
            bottom: 24px;
            right: 24px;
            background: #10b981;
            color: #fff;
            padding: 12px 20px;
            border-radius: 8px;
            font-size: 13px;
            font-weight: 600;
            box-shadow: 0 4px 16px rgba(0,0,0,0.4);
            transform: translateY(100px);
            opacity: 0;
            transition: all 0.25s ease;
            z-index: 9999;
        }}
        #toast.show {{
            transform: translateY(0);
            opacity: 1;
        }}
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(-4px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <div class="logo-icon">⚡</div>
                <div>
                    <h1>Human Approval Dashboard</h1>
                    <div class="subtitle">{html.escape(settings.app_name)} • Protected Admin Control</div>
                </div>
            </div>
            <div class="header-actions">
                <a href="/approvals" class="btn btn-refresh">🔄 Refresh Requests</a>
            </div>
        </header>

        {toast_html}

        <div class="card-list">
            {''.join(cards_html)}
        </div>
    </div>

    <div id="toast">Copied to clipboard!</div>

    <script>
        function copyText(text, btn) {{
            navigator.clipboard.writeText(text).then(() => {{
                showToast("Copied to clipboard!");
                if (btn) {{
                    const orig = btn.innerText;
                    btn.innerText = "✓ Copied!";
                    setTimeout(() => btn.innerText = orig, 1800);
                }}
            }}).catch(() => {{
                // fallback
                const ta = document.createElement("textarea");
                ta.value = text;
                document.body.appendChild(ta);
                ta.select();
                document.execCommand("copy");
                document.body.removeChild(ta);
                showToast("Copied to clipboard!");
            }});
        }}

        function showToast(msg) {{
            const t = document.getElementById("toast");
            t.innerText = msg;
            t.classList.add("show");
            setTimeout(() => t.classList.remove("show"), 2200);
        }}
    </script>
</body>
</html>
"""


def register_dashboard(app, approvals: ApprovalStore):
    """Registers password-protected /approvals dashboard routes onto FastAPI."""

    @app.get("/approvals", response_class=HTMLResponse)
    async def dashboard_view(
        request: Request,
        authenticated: bool = Depends(verify_dashboard_access),
    ):
        settings = get_settings()
        items = approvals.list_all()
        msg = request.query_params.get("message", "")
        active_id = request.query_params.get("active_id", "")
        content = build_dashboard_html(items, message=msg, active_id=active_id)
        response = HTMLResponse(content)

        expected_password = settings.admin_password or settings.oauth_signing_secret or "admin123"
        q_key = request.query_params.get("key") or request.query_params.get("password")
        if q_key:
            response.set_cookie("mcp_admin_token", expected_password, httponly=True, max_age=86400, samesite="lax")
        return response

    @app.post("/approvals/{approval_id}/ui-approve")
    async def dashboard_approve(
        approval_id: str,
        request: Request,
        authenticated: bool = Depends(verify_dashboard_access),
    ):
        settings = get_settings()
        expected_password = settings.admin_password or settings.oauth_signing_secret or "admin123"
        try:
            appr = approvals.approve(approval_id)
            if "application/json" in request.headers.get("accept", ""):
                return JSONResponse({"status": "ok", "approval_id": appr.approval_id, "approved": appr.approved})

            redirect_url = f"/approvals?message=Request+{approval_id}+has+been+approved!+You+can+now+copy+the+prompt+below+for+ChatGPT.&active_id={approval_id}"
            q_key = request.query_params.get("key") or request.query_params.get("password")
            if q_key:
                redirect_url += f"&key={q_key}"

            response = RedirectResponse(redirect_url, status_code=303)
            response.set_cookie("mcp_admin_token", expected_password, httponly=True, max_age=86400, samesite="lax")
            return response
        except KeyError:
            raise HTTPException(status_code=404, detail="Approval not found or expired")
