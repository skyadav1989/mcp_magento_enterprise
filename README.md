# Magento MCP Enterprise Gateway

A secure, multi-tenant Model Context Protocol (MCP) gateway connecting AI agents (such as OpenAI ChatGPT, Claude, and local LLMs) with Adobe Commerce / Magento 2 stores.

Built with **FastAPI**, **Streamable HTTP MCP**, **OAuth 2.1 + PKCE (S256)**, **Fernet Secret Encryption**, **Role-Based Access Control (RBAC)**, and a **Human-in-the-Loop Web Approval Dashboard**.

---

## 🌟 Key Features

- **Streamable HTTP MCP**: Implements the official Model Context Protocol Streamable HTTP transport at `/mcp`.
- **OAuth 2.1 + PKCE (S256)**: End-to-end authorization code flow with single-use cryptographic authorization codes and SHA-256 PKCE challenge verification.
- **Zero-Token-Exposure Security**: Magento Integration Access Tokens are encrypted at rest with Fernet (`cryptography.fernet`) and never placed inside client JWT tokens.
- **Multi-Tenant Isolation**: Stores and customer credentials are partitioned deterministically by OAuth `subject` and `tenant_id`.
- **Role-Based Access Control (RBAC)**:
  - `support_agent`: Read-only access (`get_orders_by_status`, `get_product_by_sku`, `get_product_list`).
  - `cms_admin` / `admin`: Full access (`get_orders_by_status`, `get_product_by_sku`, `get_product_list`, `update_product_description`, `add_media_for_sku`).
- **Human-in-the-Loop Approval Workflow**:
  - High-risk operations (e.g. `update_product_description`, `add_media_for_sku`) pause automatically and issue an `approval_id`.
  - Built-in password-protected **Web Approval Dashboard** at `/approvals` with live image preview & 1-click approvals.
  - Instant prompt generation for ChatGPT.
- **Full Test Suite & Diagnostics**:
  - 34 unit & integration test cases (`pytest`).
  - 16-point system verification runner (`verify_gateway.py`).
  - Complete live sequence runner (`auth_flow_sequence.py`).

---

## 🛠️ MCP Tool Catalog

| Tool Name | Allowed Roles | Description | Requires Approval |
| :--- | :--- | :--- | :---: |
| `get_orders_by_status` | `support_agent`, `cms_admin`, `admin` | Fetches store orders filtered by Magento order status (`pending`, `processing`, `complete`, etc.) with pagination. | No |
| `get_product_by_sku` | `support_agent`, `cms_admin`, `admin` | Fetches detailed product information (ID, name, price, status, type, attributes, media entries) by SKU. | No |
| `get_product_list` | `support_agent`, `cms_admin`, `admin` | Lists catalog products with pagination (`page_size`, `current_page`) and optional name search keyword filter. | No |
| `update_product_description` | `cms_admin`, `admin` | Updates product description by SKU via Magento REST API. | **Yes** (Human approval required) |
| `add_media_for_sku` | `cms_admin`, `admin` | Uploads product image/media (base64 data, label, mime type, roles) for a given SKU. | **Yes** (Human approval required) |

---

## 🚀 Local Quickstart

### 1. Clone & Set Up Virtual Environment

```bash
git clone https://github.com/skyadav1989/mcp_magento_enterprise.git
cd mcp_magento_enterprise

# Create and activate virtual environment
python -m venv .venv
# Windows (PowerShell):
.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment

Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

Ensure the key configurations are set for local development:
```dotenv
HOST=0.0.0.0
PORT=8000
MCP_RESOURCE_URL=http://localhost:8000/mcp
OAUTH_ISSUER_URL=http://localhost:8000
OAUTH_ALLOWED_REDIRECT_URIS=http://localhost:3000/callback,https://chatgpt.com/connector_platform_oauth_redirect
DATABASE_URL=sqlite:///./magento_mcp.db
CONNECTION_ENCRYPTION_KEY=<generated-fernet-key>
OAUTH_SIGNING_SECRET=<strong-random-secret>
ADMIN_PASSWORD=admin123
```

### 3. Start the Gateway

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Verify service status:
```bash
curl http://localhost:8000/health
```

---

## 🧪 Testing & Diagnostics

### Run the Pytest Suite (30 Tests)
```bash
pytest -v
```

### Run Full System Diagnostics
Validates health, metadata discovery, cryptography, database persistence, PKCE authorization, JWT minting, approval security, and RBAC matrix:
```bash
python verify_gateway.py
```

### Run End-to-End Authentication & Tool Sequence
Executes the live sequence in real-time and prints all keys and payloads:
```bash
python auth_flow_sequence.py
```

---

## 🛡️ Human Approval Web Dashboard (`/approvals`)

The gateway includes a password-protected dashboard to review and approve sensitive actions intercepted by the gateway.

### Accessing the Dashboard
- **Local:** [http://localhost:8000/approvals](http://localhost:8000/approvals)  
  *(Direct 1-click bypass: [http://localhost:8000/approvals?key=admin123](http://localhost:8000/approvals?key=admin123))*
- **Production (Render):** `https://mcp-magento-enterprise.onrender.com/approvals?key=admin123`

### Default Login
- **Username:** `admin`
- **Password:** Configured via `ADMIN_PASSWORD` (default: `admin123`)

### How the Workflow Operates
1. **ChatGPT Initiates Update:**
   When ChatGPT attempts to update a product description, the gateway intercepts the request and returns:
   ```json
   {
     "approval_required": true,
     "approval_id": "bUkHzJbdHoxMnWmSWG3DEov0",
     "expires_at": 1791533499.1,
     "message": "Human approval is required before the product description can be updated."
   }
   ```
2. **Review on Dashboard:**
   Open `/approvals`. The pending card displays the target SKU, description preview, tenant ID, and expiration countdown.
3. **Approve with 1 Click:**
   Click **"✓ Approve This Request"**. The dashboard signs off on the approval and provides a ready-to-paste prompt.
4. **Retry in ChatGPT:**
   Paste the generated prompt back to ChatGPT:
   > *"The request has been approved. Please retry updating the product description for SKU OPTT34060 with approval_id: `bUkHzJbdHoxMnWmSWG3DEov0`."*
5. **Execution:**
   ChatGPT retries the tool with the `approval_id`. The gateway consumes the approval, updates Magento via `/rest/V1/products/{sku}`, and reports success.

---

## ☁️ Production Deployment (Render)

### Production Endpoint
- **Public MCP Server URL:** `https://mcp-magento-enterprise.onrender.com/mcp`
- **OAuth Issuer URL:** `https://mcp-magento-enterprise.onrender.com`
- **Approval Dashboard:** `https://mcp-magento-enterprise.onrender.com/approvals`

### Deploying to Render
1. Push this repository to GitHub.
2. In Render Dashboard, click **New > Web Service** and select this repository.
3. The build and start commands are pre-configured in [`render.yaml`](render.yaml):
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
4. In the **Environment** tab, copy the contents of [`render.env`](render.env) into your environment variables.

---

## 🔒 Security Architecture

```
                    ┌────────────────────────────┐
                    │      OpenAI ChatGPT        │
                    └─────────────┬──────────────┘
                                  │ 1. OAuth 2.1 + PKCE S256
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Magento MCP Gateway                         │
│                                                                 │
│  ┌─────────────────────────┐       ┌─────────────────────────┐  │
│  │   OAuth 2.1 Auth Server │       │ Streamable HTTP /mcp    │  │
│  │   (PKCE S256 Verifier)  │       │ (RBAC & AuthContext)    │  │
│  └────────────┬────────────┘       └────────────┬────────────┘  │
│               │                                 │               │
│               ▼                                 ▼               │
│  ┌─────────────────────────┐       ┌─────────────────────────┐  │
│  │ Encrypted SQLite/Postgres│      │ Human Approval Store    │  │
│  │ (Fernet Integration Key)│       │ (Password Dashboard)    │  │
│  └─────────────────────────┘       └─────────────────────────┘  │
└─────────────────────────────────┬───────────────────────────────┘
                                  │ 2. Authenticated REST Call
                                  ▼
                    ┌────────────────────────────┐
                    │   Magento 2 / Commerce     │
                    │   REST API (/rest/V1)      │
                    └────────────────────────────┘
```

- **Tokens at Rest:** Stored in database table `magento_connections` encrypted using AES-128-CBC / HMAC-SHA256 (Fernet).
- **One-Time Approvals:** Once consumed by an update tool call, approvals are deleted immediately from memory to prevent replay attacks.
- **DNS Rebinding & Host Protection:** Configured with `TransportSecuritySettings` restricting allowed hosts and origins.

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
