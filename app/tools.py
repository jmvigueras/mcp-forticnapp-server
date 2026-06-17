"""
FortiCNAPP Tools Implementation for MCP Server

Business logic for Lacework/FortiCNAPP operations including:
- Health check and configuration validation
- Agent token management
- Container vulnerability scanning with deduplication
"""

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .cnapp_client import FortiCNAPPClient

logger = logging.getLogger(__name__)


class FortiCNAPPTools:
    """FortiCNAPP tools implementation"""

    @staticmethod
    def create_client(
        base_url: str,
        key_id: str,
        key_secret: str,
        timeout: int = 300,
        token_expiry: int = 3600,
    ) -> FortiCNAPPClient:
        """Create FortiCNAPP client instance"""
        return FortiCNAPPClient(
            base_url=base_url,
            key_id=key_id,
            key_secret=key_secret,
            timeout=timeout,
            token_expiry=token_expiry,
        )

    @staticmethod
    def validate_config(
        base_url: str, key_id: str, key_secret: str
    ) -> Dict[str, Any]:
        """Validate FortiCNAPP configuration settings"""
        issues: List[str] = []

        if not key_secret:
            issues.append("FORTICNAPP_KEY_SECRET not configured")
        if not key_id:
            issues.append("FORTICNAPP_KEY_ID not configured")
        if not base_url:
            issues.append("FORTICNAPP_BASE_URL not configured")
        else:
            # Normalize: add https:// if missing
            if not base_url.startswith(("http://", "https://")):
                base_url = f"https://{base_url}"

        return {
            "success": True,
            "message": "Configuration validation completed",
            "data": {
                "valid": len(issues) == 0,
                "issues": issues,
                "config": {
                    "base_url": base_url,
                    "key_id_configured": bool(key_id),
                    "key_secret_configured": bool(key_secret),
                },
            },
        }

    @staticmethod
    def health_check(
        base_url: str, key_id: str, key_secret: str
    ) -> Dict[str, Any]:
        """Check FortiCNAPP service health and connectivity"""
        try:
            # 1. Validate config
            config_result = FortiCNAPPTools.validate_config(base_url, key_id, key_secret)
            if not config_result["data"]["valid"]:
                return {
                    "success": False,
                    "message": "Configuration validation failed",
                    "data": {
                        "status": "unhealthy",
                        "config_valid": False,
                        "issues": config_result["data"]["issues"],
                    },
                }

            # 2. Test token retrieval
            client = FortiCNAPPTools.create_client(base_url, key_id, key_secret)
            connected = client.check_connection()

            if not connected:
                return {
                    "success": False,
                    "message": "Failed to connect to FortiCNAPP API",
                    "data": {
                        "status": "unhealthy",
                        "config_valid": True,
                        "token_obtained": False,
                    },
                }

            # 3. Test API call
            api_result = client.get("/api/v2/AgentAccessTokens")
            api_working = api_result.get("success", False)

            return {
                "success": True,
                "message": "FortiCNAPP health check completed successfully",
                "data": {
                    "status": "healthy",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "config_valid": True,
                    "token_obtained": True,
                    "api_available": api_working,
                },
            }

        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                "success": False,
                "message": f"Health check failed: {str(e)}",
                "data": {"status": "unhealthy"},
            }

    @staticmethod
    def get_agent_tokens(
        base_url: str, key_id: str, key_secret: str
    ) -> Dict[str, Any]:
        """Retrieve Lacework agent access tokens"""
        try:
            client = FortiCNAPPTools.create_client(base_url, key_id, key_secret)
            result = client.get("/api/v2/AgentAccessTokens")

            if result["success"]:
                return {
                    "success": True,
                    "message": "Agent access tokens retrieved successfully",
                    "data": result["data"],
                }
            else:
                return {
                    "success": False,
                    "message": result.get("error", "Unknown error"),
                    "data": {},
                }

        except Exception as e:
            logger.error(f"Error getting agent tokens: {e}")
            return {
                "success": False,
                "message": f"Error getting agent tokens: {str(e)}",
                "data": {},
            }

    @staticmethod
    def scan_image_vulnerabilities(
        base_url: str,
        key_id: str,
        key_secret: str,
        image_digest: str,
        days_back: int = 3,
        deduplicate: bool = True,
    ) -> Dict[str, Any]:
        """
        Scan Docker image for vulnerabilities using FortiCNAPP/Lacework.

        Args:
            base_url: Lacework API base URL
            key_id: Lacework key ID
            key_secret: Lacework key secret
            image_digest: Docker image digest (sha256:...)
            days_back: Number of days to look back for scan data
            deduplicate: Remove duplicate vulnerabilities across layers

        Returns:
            Vulnerability scan results with summary and severity breakdown
        """
        try:
            client = FortiCNAPPTools.create_client(base_url, key_id, key_secret)

            # Calculate time range
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=days_back)

            # Prepare search payload
            payload = {
                "timeFilter": {
                    "startTime": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "endTime": end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                },
                "filters": [
                    {
                        "field": "evalCtx.image_info.digest",
                        "expression": "eq",
                        "value": image_digest,
                    }
                ],
                "returns": [
                    "imageId",
                    "severity",
                    "status",
                    "vulnId",
                    "evalCtx",
                    "fixInfo",
                    "featureKey",
                ],
            }

            logger.info(
                f"Scanning image digest: {image_digest} (deduplicate: {deduplicate})"
            )

            result = client.post(
                "/api/v2/Vulnerabilities/Containers/search", payload
            )

            if not result["success"]:
                return {
                    "success": False,
                    "message": f"Vulnerability scan failed: {result.get('error')}",
                    "data": {},
                }

            vulnerability_data = result["data"]

            # Handle empty results
            if (
                not vulnerability_data
                or not isinstance(vulnerability_data, dict)
                or not vulnerability_data.get("data")
            ):
                return {
                    "success": True,
                    "message": "No vulnerability data found for this image digest",
                    "data": {
                        "image_digest": image_digest,
                        "scan_status": "no_data",
                        "total_packages": 0,
                        "vulnerabilities": 0,
                        "summary": "No scan data available for this image",
                    },
                }

            # Process and summarize
            scan_data = vulnerability_data["data"]
            summary = FortiCNAPPTools._process_vulnerability_data(
                scan_data, image_digest, deduplicate
            )

            return {
                "success": True,
                "message": "Vulnerability scan completed successfully",
                "data": summary,
            }

        except Exception as e:
            logger.error(f"Vulnerability scan failed: {e}")
            return {
                "success": False,
                "message": f"Vulnerability scan failed: {str(e)}",
                "data": {},
            }

    @staticmethod
    def _process_vulnerability_data(
        scan_data: list, image_digest: str, deduplicate: bool = True
    ) -> Dict[str, Any]:
        """Process vulnerability scan data and create clean summary with deduplication"""

        # Extract image info from first entry
        image_info: Dict[str, Any] = {}
        if (
            scan_data
            and scan_data[0].get("evalCtx", {}).get("image_info")
        ):
            img_info = scan_data[0]["evalCtx"]["image_info"]
            image_info = {
                "registry": img_info.get("registry", ""),
                "repository": img_info.get("repo", ""),
                "tags": img_info.get("tags", []),
                "size": img_info.get("size", 0),
                "scan_status": img_info.get("status", "unknown"),
            }

        # Separate good/vulnerable packages
        total_entries = len(scan_data)
        vulnerabilities = [
            item for item in scan_data if item.get("status") != "GOOD"
        ]
        good_packages = total_entries - len(vulnerabilities)
        raw_vulnerability_count = len(vulnerabilities)

        # Deduplicate
        if deduplicate and vulnerabilities:
            unique_vulns: Dict[str, Any] = {}
            for vuln in vulnerabilities:
                feature = vuln.get("featureKey", {})
                key = (
                    f"{vuln.get('vulnId', 'unknown')}_"
                    f"{feature.get('name', 'unknown')}_"
                    f"{feature.get('version', 'unknown')}"
                )

                if key not in unique_vulns:
                    unique_vulns[key] = vuln
                else:
                    # Keep the one with fix info if available
                    existing_fixable = unique_vulns[key].get(
                        "fixInfo", {}
                    ).get("fix_available") in [1, "Yes", True]
                    current_fixable = vuln.get("fixInfo", {}).get(
                        "fix_available"
                    ) in [1, "Yes", True]

                    if current_fixable and not existing_fixable:
                        unique_vulns[key] = vuln

            vulnerabilities = list(unique_vulns.values())
            logger.info(
                f"Deduplication: {raw_vulnerability_count} -> {len(vulnerabilities)} vulnerabilities"
            )

        # Count fixable
        fixable_vulns = len(
            [
                v
                for v in vulnerabilities
                if v.get("fixInfo", {}).get("fix_available") in [1, "Yes", True]
            ]
        )

        # Count by severity
        severity_counts: Dict[str, int] = {}
        critical_high_vulns: List[Dict[str, Any]] = []

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "Unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            if severity in ["Critical", "High"]:
                feature = vuln.get("featureKey", {})
                critical_high_vulns.append(
                    {
                        "vuln_id": vuln.get("vulnId", "N/A"),
                        "severity": severity,
                        "package": f"{feature.get('name', 'unknown')}:{feature.get('version', 'unknown')}",
                        "fixable": vuln.get("fixInfo", {}).get("fix_available")
                        in [1, "Yes", True],
                    }
                )

        # Sort critical/high: Critical first
        critical_high_vulns.sort(
            key=lambda x: (x["severity"] != "Critical", x["vuln_id"])
        )

        # Namespace summary
        namespace_summary: Dict[str, Dict[str, int]] = {}
        for item in scan_data:
            namespace = item.get("featureKey", {}).get("namespace", "unknown")
            if namespace not in namespace_summary:
                namespace_summary[namespace] = {"total": 0, "vulnerable": 0}
            namespace_summary[namespace]["total"] += 1
            if item.get("status") != "GOOD":
                namespace_summary[namespace]["vulnerable"] += 1

        # Security status
        if len(vulnerabilities) == 0:
            security_status = "EXCELLENT"
            security_message = "No vulnerabilities detected"
        else:
            critical_high_count = severity_counts.get(
                "Critical", 0
            ) + severity_counts.get("High", 0)
            if critical_high_count > 0:
                security_status = "CRITICAL"
                security_message = f"Contains {critical_high_count} unique critical/high severity vulnerabilities"
            else:
                security_status = "NEEDS_ATTENTION"
                security_message = f"Contains {len(vulnerabilities)} unique vulnerabilities (no critical/high)"

        return {
            "image_digest": image_digest,
            "scan_timestamp": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "image_info": image_info,
            "security_status": security_status,
            "security_message": security_message,
            "deduplication_info": {
                "enabled": deduplicate,
                "raw_vulnerability_count": raw_vulnerability_count,
                "unique_vulnerability_count": len(vulnerabilities),
                "duplicates_removed": raw_vulnerability_count
                - len(vulnerabilities),
            },
            "summary": {
                "total_packages": total_entries,
                "clean_packages": good_packages,
                "total_vulnerabilities": len(vulnerabilities),
                "fixable_vulnerabilities": fixable_vulns,
            },
            "severity_breakdown": severity_counts,
            "critical_high_details": critical_high_vulns[:10],
            "namespace_summary": dict(
                sorted(
                    namespace_summary.items(),
                    key=lambda x: x[1]["total"],
                    reverse=True,
                )[:5]
            ),
        }
