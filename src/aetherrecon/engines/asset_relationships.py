"""
Asset Relationship Intelligence Engine
-----------------------------------------
Maps relationships between discovered assets to build a complete
picture of the target's infrastructure.

domain ├── subdomains ├── IPs ├── ASN ├── CDN ├── WAF
       ├── technologies ├── APIs ├── auth portals └── cloud assets
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any
from enum import Enum


class AssetType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    ASN = "asn"
    CDN = "cdn"
    WAF = "waf"
    TECHNOLOGY = "technology"
    API = "api"
    AUTH_PORTAL = "auth_portal"
    CLOUD_ASSET = "cloud_asset"
    SERVICE = "service"
    CERTIFICATE = "certificate"
    DNS_RECORD = "dns_record"


class RelationshipType(str, Enum):
    RESOLVES_TO = "resolves_to"          # domain → IP
    BELONGS_TO = "belongs_to"            # IP → ASN
    PROTECTED_BY = "protected_by"        # domain → WAF/CDN
    RUNS = "runs"                        # host → technology
    EXPOSES = "exposes"                  # host → service/API
    HAS_CERTIFICATE = "has_certificate"  # domain → cert
    CHILD_OF = "child_of"               # subdomain → domain
    HOSTS = "hosts"                      # IP → service
    CONNECTED_TO = "connected_to"        # generic relationship


@dataclass
class Asset:
    """A single discovered asset in the attack surface."""
    asset_type: AssetType
    value: str
    metadata: dict[str, Any] = field(default_factory=dict)
    source: str = ""
    confidence: str = "medium"

    @property
    def key(self) -> str:
        return f"{self.asset_type.value}:{self.value}"


@dataclass
class AssetRelationship:
    """A relationship between two assets."""
    source: Asset
    target: Asset
    relationship: RelationshipType
    metadata: dict[str, Any] = field(default_factory=dict)


class AssetRelationshipEngine:
    """
    Builds and queries the asset relationship graph.

    Features:
    - ASN mapping
    - Reverse IP lookup correlation
    - Cloud provider detection
    - CDN/WAF identification
    - Service clustering
    - Technology relationship mapping
    """

    def __init__(self):
        self._assets: dict[str, Asset] = {}
        self._relationships: list[AssetRelationship] = []
        self._cloud_providers = {
            "amazonaws.com": "AWS",
            "cloudfront.net": "AWS CloudFront",
            "azurewebsites.net": "Azure",
            "azure-api.net": "Azure",
            "blob.core.windows.net": "Azure Blob",
            "googleapis.com": "Google Cloud",
            "firebaseio.com": "Firebase",
            "appspot.com": "Google App Engine",
            "herokuapp.com": "Heroku",
            "digitaloceanspaces.com": "DigitalOcean Spaces",
            "netlify.app": "Netlify",
            "vercel.app": "Vercel",
            "pages.dev": "Cloudflare Pages",
            "workers.dev": "Cloudflare Workers",
        }
        self._cdn_indicators = {
            "cloudflare": "Cloudflare",
            "akamai": "Akamai",
            "fastly": "Fastly",
            "cloudfront": "CloudFront",
            "maxcdn": "MaxCDN",
            "incapsula": "Imperva/Incapsula",
            "sucuri": "Sucuri",
        }
        self._waf_indicators = {
            "cloudflare": "Cloudflare WAF",
            "akamai": "Akamai Kona",
            "imperva": "Imperva WAF",
            "incapsula": "Incapsula WAF",
            "sucuri": "Sucuri WAF",
            "f5": "F5 Big-IP",
            "barracuda": "Barracuda WAF",
            "fortinet": "FortiWeb",
            "aws-waf": "AWS WAF",
            "modsecurity": "ModSecurity",
        }

    def add_asset(self, asset_type: AssetType, value: str,
                  source: str = "", metadata: dict | None = None,
                  confidence: str = "medium") -> Asset:
        """Register a discovered asset."""
        asset = Asset(
            asset_type=asset_type,
            value=value,
            source=source,
            metadata=metadata or {},
            confidence=confidence,
        )
        self._assets[asset.key] = asset
        return asset

    def add_relationship(self, source: Asset, target: Asset,
                          relationship: RelationshipType,
                          metadata: dict | None = None):
        """Record a relationship between two assets."""
        rel = AssetRelationship(
            source=source,
            target=target,
            relationship=relationship,
            metadata=metadata or {},
        )
        self._relationships.append(rel)

    def ingest_scan_context(self, context: dict[str, Any]):
        """
        Build the asset graph from the shared scan context.
        Automatically detects relationships.
        """
        target = context.get("target", "")
        if target:
            root = self.add_asset(AssetType.DOMAIN, target, "scan_target")

        # Subdomains → domain relationship
        for sub in context.get("subdomains", []):
            sub_asset = self.add_asset(AssetType.SUBDOMAIN, sub, "subdomain_enum")
            if target:
                self.add_relationship(sub_asset, root, RelationshipType.CHILD_OF)
            # Cloud detection
            self._detect_cloud(sub, sub_asset)

        # IPs
        for ip in context.get("ips", []):
            ip_asset = self.add_asset(AssetType.IP, ip, "dns_enum")
            if target:
                self.add_relationship(root, ip_asset, RelationshipType.RESOLVES_TO)

        # Open ports → services
        for port_info in context.get("open_ports", []):
            if isinstance(port_info, dict):
                host = port_info.get("host", target)
                port = port_info.get("port", 0)
                service = port_info.get("service", "unknown")
                svc_asset = self.add_asset(
                    AssetType.SERVICE, f"{host}:{port}",
                    "port_scan",
                    {"port": port, "service": service, "banner": port_info.get("banner", "")},
                )

        # Technologies
        for tech in context.get("technologies", []):
            if isinstance(tech, dict):
                host = tech.get("host", target)
                name = tech.get("name", "")
                if name:
                    tech_asset = self.add_asset(
                        AssetType.TECHNOLOGY, name, "tech_fingerprint",
                        {"version": tech.get("version", ""), "category": tech.get("category", "")},
                    )
                    # Check for WAF/CDN
                    self._detect_waf_cdn(name, tech_asset)

        # HTTP services — detect auth portals and APIs
        for svc in context.get("http_services", []):
            if isinstance(svc, dict):
                url = svc.get("url", "")
                title = svc.get("title", "").lower()

                # Auth portal detection
                auth_patterns = ["login", "admin", "signin", "auth", "dashboard", "portal"]
                if any(p in url.lower() or p in title for p in auth_patterns):
                    self.add_asset(AssetType.AUTH_PORTAL, url, "http_probe",
                                   {"title": svc.get("title", "")})

                # API detection
                api_patterns = ["/api", "/v1", "/v2", "/graphql", "/swagger", "/rest"]
                if any(p in url.lower() for p in api_patterns):
                    self.add_asset(AssetType.API, url, "http_probe")

    def _detect_cloud(self, hostname: str, asset: Asset):
        """Detect if a hostname points to cloud infrastructure."""
        for domain, provider in self._cloud_providers.items():
            if domain in hostname.lower():
                cloud_asset = self.add_asset(
                    AssetType.CLOUD_ASSET, provider, "cloud_detection",
                    {"hostname": hostname},
                )
                self.add_relationship(asset, cloud_asset, RelationshipType.BELONGS_TO)
                break

    def _detect_waf_cdn(self, tech_name: str, tech_asset: Asset):
        """Detect WAF/CDN from technology name."""
        name_lower = tech_name.lower()
        for indicator, waf_name in self._waf_indicators.items():
            if indicator in name_lower:
                waf_asset = self.add_asset(AssetType.WAF, waf_name, "tech_fingerprint")
                self.add_relationship(tech_asset, waf_asset, RelationshipType.PROTECTED_BY)
                return
        for indicator, cdn_name in self._cdn_indicators.items():
            if indicator in name_lower:
                cdn_asset = self.add_asset(AssetType.CDN, cdn_name, "tech_fingerprint")
                self.add_relationship(tech_asset, cdn_asset, RelationshipType.PROTECTED_BY)
                return

    def get_assets_by_type(self, asset_type: AssetType) -> list[Asset]:
        """Get all assets of a specific type."""
        return [a for a in self._assets.values() if a.asset_type == asset_type]

    def get_relationships_for(self, asset_key: str) -> list[AssetRelationship]:
        """Get all relationships involving a specific asset."""
        return [
            r for r in self._relationships
            if r.source.key == asset_key or r.target.key == asset_key
        ]

    def get_attack_surface_summary(self) -> dict[str, Any]:
        """Generate attack surface summary from the asset graph."""
        type_counts: dict[str, int] = {}
        for asset in self._assets.values():
            t = asset.asset_type.value
            type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "total_assets": len(self._assets),
            "total_relationships": len(self._relationships),
            "asset_breakdown": type_counts,
            "cloud_providers": [
                a.value for a in self.get_assets_by_type(AssetType.CLOUD_ASSET)
            ],
            "waf_detected": [
                a.value for a in self.get_assets_by_type(AssetType.WAF)
            ],
            "cdn_detected": [
                a.value for a in self.get_assets_by_type(AssetType.CDN)
            ],
            "auth_surfaces": [
                a.value for a in self.get_assets_by_type(AssetType.AUTH_PORTAL)
            ],
            "api_endpoints": [
                a.value for a in self.get_assets_by_type(AssetType.API)
            ],
        }

    def to_graph_data(self) -> dict[str, Any]:
        """Export graph data for visualization."""
        nodes = []
        for asset in self._assets.values():
            nodes.append({
                "id": asset.key,
                "type": asset.asset_type.value,
                "value": asset.value,
                "metadata": asset.metadata,
            })

        edges = []
        for rel in self._relationships:
            edges.append({
                "source": rel.source.key,
                "target": rel.target.key,
                "relationship": rel.relationship.value,
            })

        return {"nodes": nodes, "edges": edges}
