"""
FastMCP server for FortiCNAPP (Fortinet Cloud Native Application Protection Platform)

Integrates with Lacework APIs for cloud security operations including:
- Health check and connectivity validation
- Agent token management
- Container vulnerability scanning

Run with:
    uvicorn app.server:app --host 0.0.0.0 --port 8000
"""

import json
import logging
import os
from contextlib import asynccontextmanager

from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from .tools import FortiCNAPPTools

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create MCP server
mcp = FastMCP("FortiCNAPP MCP Server")

# Environment variable names
ENV_KEY_ID = "FORTICNAPP_KEY_ID"
ENV_KEY_SECRET = "FORTICNAPP_KEY_SECRET"
ENV_BASE_URL = "FORTICNAPP_BASE_URL"
DEFAULT_BASE_URL = "lwintseemea-eu.lacework.net"


def _resolve_credentials(
    cnapp_key_id: str = "",
    cnapp_key_secret: str = "",
    cnapp_base_url: str = "",
) -> tuple[str, str, str]:
    """
    Resolve FortiCNAPP credentials from parameters or environment variables.

    Priority: explicit parameter > environment variable > default.
    Raises ValueError if required credentials are missing.
    """
    key_id = cnapp_key_id.strip() if cnapp_key_id else ""
    if not key_id:
        key_id = os.environ.get(ENV_KEY_ID, "").strip()
    if not key_id:
        raise ValueError(
            f"Key ID is required. Pass cnapp_key_id parameter or set "
            f"{ENV_KEY_ID} environment variable."
        )

    key_secret = cnapp_key_secret.strip() if cnapp_key_secret else ""
    if not key_secret:
        key_secret = os.environ.get(ENV_KEY_SECRET, "").strip()
    if not key_secret:
        raise ValueError(
            f"Key secret is required. Pass cnapp_key_secret parameter or set "
            f"{ENV_KEY_SECRET} environment variable."
        )

    base_url = cnapp_base_url.strip() if cnapp_base_url else ""
    if not base_url:
        base_url = os.environ.get(ENV_BASE_URL, DEFAULT_BASE_URL).strip()

    # Ensure base_url has https:// prefix
    if not base_url.startswith(("http://", "https://")):
        base_url = f"https://{base_url}"

    return key_id, key_secret, base_url


# ===============================
# HEALTH CHECK ENDPOINT
# ===============================


async def health_check(request):
    """Health check endpoint for liveness/readiness probes"""
    return JSONResponse({"status": "healthy", "service": "mcp-forticnapp-server"})


# ===============================
# FORTICNAPP TOOLS
# ===============================


@mcp.tool()
def cnapp_health_check(
    cnapp_key_id: str = "",
    cnapp_key_secret: str = "",
    cnapp_base_url: str = "",
) -> str:
    """Check FortiCNAPP service health and connectivity.

    Validates configuration, tests bearer token authentication, and verifies API access.

    Args:
        cnapp_key_id: FortiCNAPP API key ID (optional if FORTICNAPP_KEY_ID env var is set)
        cnapp_key_secret: FortiCNAPP API key secret (optional if FORTICNAPP_KEY_SECRET env var is set)
        cnapp_base_url: FortiCNAPP API base URL or FQDN (e.g., myaccount.lacework.net). https:// is auto-prepended if missing. Optional if FORTICNAPP_BASE_URL env var is set.
    """
    key_id, key_secret, base_url = _resolve_credentials(
        cnapp_key_id, cnapp_key_secret, cnapp_base_url
    )
    result = FortiCNAPPTools.health_check(base_url, key_id, key_secret)
    return json.dumps(result, indent=2)


@mcp.tool()
def cnapp_validate_config(
    cnapp_key_id: str = "",
    cnapp_key_secret: str = "",
    cnapp_base_url: str = "",
) -> str:
    """Validate FortiCNAPP configuration settings and credentials.

    Checks that all required environment variables or parameters are properly configured.

    Args:
        cnapp_key_id: FortiCNAPP API key ID (optional if FORTICNAPP_KEY_ID env var is set)
        cnapp_key_secret: FortiCNAPP API key secret (optional if FORTICNAPP_KEY_SECRET env var is set)
        cnapp_base_url: FortiCNAPP API base URL or FQDN (e.g., myaccount.lacework.net). https:// is auto-prepended if missing. Optional if FORTICNAPP_BASE_URL env var is set.
    """
    # For validation, we don't raise on missing - we report it
    key_id = (cnapp_key_id.strip() or os.environ.get(ENV_KEY_ID, "")).strip()
    key_secret = (cnapp_key_secret.strip() or os.environ.get(ENV_KEY_SECRET, "")).strip()
    base_url = (cnapp_base_url.strip() or os.environ.get(ENV_BASE_URL, DEFAULT_BASE_URL)).strip()

    # Ensure base_url has https:// prefix
    if base_url and not base_url.startswith(("http://", "https://")):
        base_url = f"https://{base_url}"

    result = FortiCNAPPTools.validate_config(base_url, key_id, key_secret)
    return json.dumps(result, indent=2)


@mcp.tool()
def cnapp_get_agent_tokens(
    cnapp_key_id: str = "",
    cnapp_key_secret: str = "",
    cnapp_base_url: str = "",
) -> str:
    """Retrieve FortiCNAPP/Lacework agent access tokens.

    Returns the list of agent access tokens configured in the account.

    Args:
        cnapp_key_id: FortiCNAPP API key ID (optional if FORTICNAPP_KEY_ID env var is set)
        cnapp_key_secret: FortiCNAPP API key secret (optional if FORTICNAPP_KEY_SECRET env var is set)
        cnapp_base_url: FortiCNAPP API base URL or FQDN (e.g., myaccount.lacework.net). https:// is auto-prepended if missing. Optional if FORTICNAPP_BASE_URL env var is set.
    """
    key_id, key_secret, base_url = _resolve_credentials(
        cnapp_key_id, cnapp_key_secret, cnapp_base_url
    )
    result = FortiCNAPPTools.get_agent_tokens(base_url, key_id, key_secret)
    return json.dumps(result, indent=2)


@mcp.tool()
def cnapp_scan_image_vulnerabilities(
    image_digest: str,
    cnapp_key_id: str = "",
    cnapp_key_secret: str = "",
    cnapp_base_url: str = "",
    days_back: int = 3,
    deduplicate: bool = True,
) -> str:
    """Scan a Docker container image for vulnerabilities using FortiCNAPP.

    Queries FortiCNAPP vulnerability data for a specific container image digest
    and returns a summary with severity breakdown and deduplication.

    Args:
        image_digest: Docker image digest to scan (e.g., sha256:abc123...)
        cnapp_key_id: FortiCNAPP API key ID (optional if FORTICNAPP_KEY_ID env var is set)
        cnapp_key_secret: FortiCNAPP API key secret (optional if FORTICNAPP_KEY_SECRET env var is set)
        cnapp_base_url: FortiCNAPP API base URL or FQDN (e.g., myaccount.lacework.net). https:// is auto-prepended if missing. Optional if FORTICNAPP_BASE_URL env var is set.
        days_back: Number of days to look back for scan data (default: 3)
        deduplicate: Remove duplicate vulnerabilities across layers (default: true)
    """
    key_id, key_secret, base_url = _resolve_credentials(
        cnapp_key_id, cnapp_key_secret, cnapp_base_url
    )
    result = FortiCNAPPTools.scan_image_vulnerabilities(
        base_url=base_url,
        key_id=key_id,
        key_secret=key_secret,
        image_digest=image_digest,
        days_back=days_back,
        deduplicate=deduplicate,
    )
    return json.dumps(result, indent=2)


# ===============================
# ASGI APP SETUP
# ===============================

# Create the ASGI app with health check endpoint mounted alongside MCP
mcp_app = mcp.streamable_http_app()


@asynccontextmanager
async def lifespan(app):
    """Manage MCP server lifespan within the parent Starlette app"""
    async with mcp_app.router.lifespan_context(mcp_app):
        yield


app = Starlette(
    routes=[
        Route("/health", health_check),
        Mount("/", app=mcp_app),
    ],
    lifespan=lifespan,
)
