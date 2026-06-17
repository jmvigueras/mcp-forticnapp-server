"""
FortiCNAPP (Lacework) API Client for MCP Server

Handles bearer token authentication with automatic caching and refresh.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)

# Default retry configuration
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_BACKOFF = 1.0  # seconds


class FortiCNAPPClient:
    """FortiCNAPP (Lacework) API client with bearer token authentication"""

    def __init__(
        self,
        base_url: str,
        key_id: str,
        key_secret: str,
        timeout: int = 300,
        token_expiry: int = 3600,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_backoff: float = DEFAULT_RETRY_BACKOFF,
    ):
        """
        Initialize FortiCNAPP API client.

        Args:
            base_url: Lacework API base URL (e.g., https://myaccount.lacework.net)
            key_id: Lacework API key ID
            key_secret: Lacework API key secret (X-LW-UAKS value)
            timeout: Request timeout in seconds (default: 300)
            token_expiry: Bearer token expiry time in seconds (default: 3600)
            max_retries: Maximum number of retries for transient failures
            retry_backoff: Base backoff time in seconds between retries
        """
        # Ensure https:// prefix (FortiCNAPP always uses HTTPS)
        if not base_url.startswith(("http://", "https://")):
            base_url = f"https://{base_url}"
        self.base_url = base_url.rstrip("/")
        self.key_id = key_id
        self.key_secret = key_secret
        self.timeout = timeout
        self.token_expiry = token_expiry
        self.max_retries = max_retries
        self.retry_backoff = retry_backoff
        self.session = requests.Session()

        # Token cache
        self._token: Optional[str] = None
        self._token_expires_at: float = 0

    def _get_bearer_token(self) -> str:
        """
        Get a valid bearer token, using cache when possible.

        Returns:
            Bearer token string

        Raises:
            RuntimeError: If token cannot be obtained
        """
        current_time = time.time()

        # Return cached token if still valid (with 60s buffer)
        if self._token and self._token_expires_at > current_time + 60:
            logger.debug("Using cached Lacework bearer token")
            return self._token

        # Request new token
        token_url = f"{self.base_url}/api/v2/access/tokens"
        headers = {
            "X-LW-UAKS": self.key_secret,
            "Content-Type": "application/json",
        }
        payload = {
            "keyId": self.key_id,
            "expiryTime": self.token_expiry,
        }

        logger.info(f"Requesting new Lacework bearer token from {token_url}")

        try:
            response = requests.post(
                token_url, json=payload, headers=headers, timeout=30
            )
        except requests.RequestException as e:
            raise RuntimeError(f"Failed to request bearer token: {e}")

        if response.status_code not in [200, 201]:
            raise RuntimeError(
                f"Token request failed with status {response.status_code}: {response.text}"
            )

        token_data = response.json()
        token = token_data.get("token")
        expires_at_str = token_data.get("expiresAt")

        if not token:
            raise RuntimeError("Token not found in response")

        # Parse expiration and cache
        expires_at = datetime.fromisoformat(
            expires_at_str.replace("Z", "+00:00")
        )
        self._token = token
        self._token_expires_at = expires_at.timestamp()

        logger.info(f"Bearer token obtained, expires at {expires_at_str}")
        return token

    def clear_token_cache(self):
        """Clear the cached bearer token"""
        self._token = None
        self._token_expires_at = 0
        logger.info("Token cache cleared")

    def check_connection(self) -> bool:
        """
        Check if Lacework API is accessible by attempting token retrieval.

        Returns:
            True if connection is successful
        """
        try:
            self._get_bearer_token()
            return True
        except Exception as e:
            logger.error(f"Connection check failed: {e}")
            return False

    def _make_request(
        self, method: str, endpoint: str, data: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Make authenticated HTTP request to Lacework API with retry logic.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (should start with /)
            data: Request data for POST/PUT

        Returns:
            API response as dictionary
        """
        url = f"{self.base_url}{endpoint}"

        last_exception: Optional[Exception] = None
        for attempt in range(self.max_retries):
            try:
                # Get bearer token
                token = self._get_bearer_token()

                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                }

                response = self.session.request(
                    method=method.upper(),
                    url=url,
                    headers=headers,
                    json=data,
                    timeout=self.timeout,
                )

                logger.info(
                    f"{method.upper()} {endpoint} - Status: {response.status_code}"
                )

                # Handle empty responses
                if response.status_code == 204 or not response.content:
                    return {
                        "success": True,
                        "message": "Operation completed successfully",
                        "status_code": response.status_code,
                    }

                # Handle 401 - clear token cache and retry
                if response.status_code == 401:
                    self.clear_token_cache()
                    if attempt < self.max_retries - 1:
                        logger.warning(
                            f"Auth failed on attempt {attempt + 1}, refreshing token..."
                        )
                        continue
                    return {
                        "success": False,
                        "error": "Authentication failed after token refresh",
                        "status_code": 401,
                    }

                # Handle client errors (4xx, non-401)
                if 400 <= response.status_code < 500:
                    error_msg = f"Client error {response.status_code}"
                    try:
                        error_detail = response.json()
                        if "message" in error_detail:
                            error_msg += f": {error_detail['message']}"
                    except Exception:
                        error_msg += f": {response.text[:200]}"

                    return {
                        "success": False,
                        "error": error_msg,
                        "status_code": response.status_code,
                    }

                # Handle server errors (5xx) with retry
                if response.status_code >= 500:
                    last_exception = Exception(
                        f"Server error {response.status_code}: {response.text[:200]}"
                    )
                    if attempt < self.max_retries - 1:
                        wait_time = self.retry_backoff * (2**attempt)
                        logger.warning(
                            f"Server error on attempt {attempt + 1}/{self.max_retries}, "
                            f"retrying in {wait_time}s"
                        )
                        time.sleep(wait_time)
                        continue
                    return {
                        "success": False,
                        "error": str(last_exception),
                        "status_code": response.status_code,
                    }

                # Success
                try:
                    result = response.json()
                except Exception:
                    result = {"raw_response": response.text[:500]}

                return {
                    "success": True,
                    "data": result,
                    "status_code": response.status_code,
                }

            except RuntimeError as e:
                # Token retrieval failure
                return {
                    "success": False,
                    "error": str(e),
                    "status_code": 0,
                }

            except requests.exceptions.ConnectionError as e:
                last_exception = e
                if attempt < self.max_retries - 1:
                    wait_time = self.retry_backoff * (2**attempt)
                    logger.warning(
                        f"Connection error on attempt {attempt + 1}/{self.max_retries}, "
                        f"retrying in {wait_time}s: {e}"
                    )
                    time.sleep(wait_time)
                else:
                    logger.error(
                        f"Connection failed after {self.max_retries} attempts: {e}"
                    )

            except requests.exceptions.Timeout as e:
                last_exception = e
                if attempt < self.max_retries - 1:
                    wait_time = self.retry_backoff * (2**attempt)
                    logger.warning(
                        f"Timeout on attempt {attempt + 1}/{self.max_retries}, "
                        f"retrying in {wait_time}s: {e}"
                    )
                    time.sleep(wait_time)
                else:
                    logger.error(
                        f"Request timed out after {self.max_retries} attempts: {e}"
                    )

            except requests.exceptions.RequestException as e:
                logger.error(f"Request failed: {e}")
                return {
                    "success": False,
                    "error": f"Request failed: {str(e)}",
                    "status_code": 0,
                }

        # All retries exhausted
        return {
            "success": False,
            "error": f"Request failed after {self.max_retries} attempts: {str(last_exception)}",
            "status_code": 0,
        }

    def get(self, endpoint: str) -> Dict[str, Any]:
        """GET request"""
        return self._make_request("GET", endpoint)

    def post(self, endpoint: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """POST request"""
        return self._make_request("POST", endpoint, data)

    def put(self, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """PUT request"""
        return self._make_request("PUT", endpoint, data)

    def delete(self, endpoint: str) -> Dict[str, Any]:
        """DELETE request"""
        return self._make_request("DELETE", endpoint)
