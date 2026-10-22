"""Runtime configuration.

All settings come from environment variables (optionally loaded from a ``.env`` file).
Nothing host-specific is hard-coded: hostnames, keys and network ranges live in ``.env``.
List-valued settings accept comma-separated strings, e.g.
``ALLOWED_SCAN_CIDRS=192.168.50.0/24,10.0.0.0/24``.
Nested scoring weights use a double underscore, e.g. ``SCORING__EXPOSURE_LAN=0.6``.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

#: Address space that is never routable on the public Internet. Only CIDRs inside these
#: ranges may ever appear in ``ALLOWED_SCAN_CIDRS``.
NON_PUBLIC_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT / Tailscale
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),  # IPv6 unique local
    ipaddress.ip_network("::1/128"),
)

RFC1918 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

CsvList = Annotated[list[str], NoDecode]


def _split_csv(value: Any) -> Any:
    """Turn ``"a, b,,c"`` into ``["a", "b", "c"]``; pass lists through unchanged."""
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return value


def is_non_public_network(cidr: str) -> bool:
    """Return True if ``cidr`` lies entirely inside non-Internet-routable address space."""
    net = ipaddress.ip_network(cidr, strict=False)
    return any(
        net.version == allowed.version and net.subnet_of(allowed)  # type: ignore[arg-type]
        for allowed in NON_PUBLIC_NETWORKS
    )


class ScoringWeights(BaseModel):
    """Weights for :func:`vulntriage.scoring.score_finding`. See ``docs/SCORING.md``."""

    kev_tier_offset: float = Field(
        1000.0, description="Added to every KEV-listed finding so it outranks all non-KEV ones."
    )
    epss_scale: float = Field(100.0, description="EPSS probability (0-1) is multiplied by this.")
    exposure_internet: float = 1.0
    exposure_lan: float = 0.5
    exposure_localhost: float = 0.2
    exposure_none: float = 0.1
    cvss_weight: float = Field(1.0, description="CVSS/10 x weight, a tiebreaker (max 1 point).")
    fix_available_multiplier: float = Field(
        1.25, description="Multiplier on the EPSS x exposure part when a fixed version exists."
    )
    ransomware_bonus: float = Field(
        100.0, description="Extra points for KEV entries with known ransomware campaign use."
    )
    unknown_epss: float = Field(
        0.0, description="EPSS value assumed when no EPSS score is available."
    )

    @model_validator(mode="after")
    def _kev_tier_dominates(self) -> ScoringWeights:
        """Guarantee hard rule: every KEV finding outranks every non-KEV finding."""
        max_exposure = max(
            self.exposure_internet, self.exposure_lan, self.exposure_localhost, self.exposure_none
        )
        best_non_kev = (
            self.epss_scale * max_exposure * max(self.fix_available_multiplier, 1.0)
            + self.cvss_weight
        )
        if self.kev_tier_offset <= best_non_kev:
            raise ValueError(
                f"kev_tier_offset ({self.kev_tier_offset}) must exceed the best possible "
                f"non-KEV score ({best_non_kev:.1f})"
            )
        return self


class Settings(BaseSettings):
    """All VulnTriage settings. Field names map 1:1 to upper-case environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        extra="ignore",
    )

    # --- storage -------------------------------------------------------------------
    database_url: str = "sqlite:///./data/vulntriage.db"
    data_dir: Path = Path("./data")
    reports_dir: Path = Path("./reports")
    offline: bool = Field(False, description="Never contact external feeds; use the cache only.")

    # --- scanning ------------------------------------------------------------------
    docker_host: str = "unix:///var/run/docker.sock"
    trivy_bin: str = "trivy"
    grype_bin: str = "grype"
    enable_grype: bool = False
    scan_timeout_seconds: int = 900
    trivy_extra_args: CsvList = []
    exclude_images: CsvList = Field(
        default_factory=list, description="Glob patterns of image refs to skip."
    )
    own_image_patterns: CsvList = Field(
        default_factory=list,
        description="Globs of images you build yourself (fixes become package bumps/rebuilds).",
    )
    host_scan_targets: CsvList = Field(
        default_factory=list,
        description="'name=/path' pairs scanned with `trivy rootfs` (OS packages of a host).",
    )
    fs_scan_targets: CsvList = Field(
        default_factory=list,
        description="'name=/path' pairs scanned with `trivy fs` (lockfiles in a directory).",
    )

    # --- threat intel ----------------------------------------------------------------
    epss_url: str = "https://api.first.org/data/v1/epss"
    kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    nvd_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    osv_url: str = "https://api.osv.dev/v1/query"
    nvd_api_key: SecretStr | None = None
    nvd_mode: Literal["missing", "always", "never"] = Field(
        "missing",
        description="'missing' only queries NVD for CVEs whose CVSS the scanner did not supply.",
    )
    nvd_max_per_run: int = Field(200, description="Cap on NVD lookups per enrichment run.")
    osv_max_per_run: int = Field(300, description="Cap on OSV package queries per run.")
    intel_ttl_hours: int = 24
    nvd_ttl_hours: int = 24 * 7
    http_timeout_seconds: float = 30.0
    http_max_retries: int = 4

    # --- exposure --------------------------------------------------------------------
    allowed_scan_cidrs: CsvList = Field(default_factory=lambda: list(RFC1918))
    nmap_enabled: bool = False
    nmap_bin: str = "nmap"
    nmap_targets: CsvList = Field(default_factory=list)
    nmap_top_ports: int = 200
    host_lan_ips: CsvList = Field(
        default_factory=list,
        description="LAN IPs of the Docker host, used to match nmap results to published ports.",
    )
    caddy_config_paths: CsvList = Field(default_factory=list)
    nginx_config_paths: CsvList = Field(
        default_factory=list, description="Files or directories (e.g. NPM's /data/nginx)."
    )
    traefik_labels: bool = True
    exposure_overrides: CsvList = Field(
        default_factory=list,
        description="'asset-name=level' pairs that force an exposure level, e.g. 'nas=lan'.",
    )
    host_exposure: Literal["internet", "lan", "localhost", "none"] = Field(
        "lan", description="Default exposure of host (rootfs) assets."
    )
    internet_hostname_patterns: CsvList = Field(
        default_factory=list,
        description="Globs of proxy hostnames reachable from the Internet, e.g. '*.example.com'.",
    )

    # --- scoring ---------------------------------------------------------------------
    scoring: ScoringWeights = ScoringWeights()
    action_threshold: float = Field(
        5.0, description="Findings scoring at or above this need action; below is noise."
    )

    # --- LLM ---------------------------------------------------------------------------
    llm_provider: Literal["mock", "anthropic", "gemini", "openai"] = "mock"
    llm_model: str | None = None
    llm_base_url: str | None = Field(None, description="Base URL for OpenAI-compatible APIs.")
    anthropic_api_key: SecretStr | None = None
    gemini_api_key: SecretStr | None = None
    openai_api_key: SecretStr | None = None
    llm_max_turns: int = 12
    llm_max_tokens: int = 4096
    report_top_n: int = 5

    # --- web / schedule / alerts ----------------------------------------------------------
    dashboard_user: str | None = None
    dashboard_password: SecretStr | None = None
    demo_mode: bool = Field(False, description="Serve the bundled demo homelab instead.")
    schedule_enabled: bool = False
    schedule_cron: str = "30 2 * * *"
    schedule_timezone: str = "UTC"

    dashboard_url: str | None = Field(None, description="Link included in alert messages.")
    alert_min_score: float = 50.0
    telegram_enabled: bool = False
    telegram_bot_token: SecretStr | None = None
    telegram_chat_id: str | None = None
    smtp_enabled: bool = False
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_starttls: bool = True
    smtp_user: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str | None = None
    smtp_to: CsvList = Field(default_factory=list)

    @field_validator(
        "trivy_extra_args",
        "exclude_images",
        "own_image_patterns",
        "host_scan_targets",
        "fs_scan_targets",
        "allowed_scan_cidrs",
        "nmap_targets",
        "host_lan_ips",
        "caddy_config_paths",
        "nginx_config_paths",
        "internet_hostname_patterns",
        "exposure_overrides",
        "smtp_to",
        mode="before",
    )
    @classmethod
    def _csv(cls, value: Any) -> Any:
        return _split_csv(value)

    @field_validator("allowed_scan_cidrs")
    @classmethod
    def _only_private_cidrs(cls, value: list[str]) -> list[str]:
        """Fail closed: a public CIDR in the allow-list is a configuration error."""
        for cidr in value:
            try:
                ok = is_non_public_network(cidr)
            except ValueError as exc:
                raise ValueError(f"invalid CIDR in ALLOWED_SCAN_CIDRS: {cidr!r}") from exc
            if not ok:
                raise ValueError(
                    f"ALLOWED_SCAN_CIDRS may only contain private ranges; refusing {cidr!r}"
                )
        return value

    def parsed_targets(self, field: str) -> list[tuple[str, str]]:
        """Parse ``name=value`` pairs from a list setting; a bare value is its own name."""
        pairs: list[tuple[str, str]] = []
        for item in getattr(self, field):
            name, sep, path = item.partition("=")
            pairs.append((name.strip(), path.strip()) if sep else (item, item))
        return pairs


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings (cached). Tests construct ``Settings`` directly."""
    return Settings()
