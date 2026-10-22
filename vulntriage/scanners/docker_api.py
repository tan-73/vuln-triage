"""Minimal, read-only Docker Engine API client (GET requests only).

Talks to the daemon over a unix socket or TCP (e.g. a docker-socket-proxy) with httpx,
so no Docker SDK is required. Only ``/containers/json`` and ``/images/{ref}/json`` are used.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
from pydantic import BaseModel, Field

log = logging.getLogger(__name__)


class PortBinding(BaseModel):
    """A container port and, if published, where it is bound on the host."""

    private_port: int
    public_port: int | None = None
    host_ip: str | None = None
    protocol: str = "tcp"


class ContainerInfo(BaseModel):
    """The subset of ``GET /containers/json`` VulnTriage needs."""

    id: str
    name: str
    image: str
    image_id: str
    state: str = "running"
    ports: list[PortBinding] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    networks: list[str] = Field(default_factory=list)
    network_mode: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)

    @classmethod
    def from_api(cls, raw: dict[str, Any]) -> ContainerInfo:
        """Build from one element of the ``/containers/json`` response."""
        names = raw.get("Names") or []
        name = names[0].lstrip("/") if names else raw.get("Id", "")[:12]
        nets = (raw.get("NetworkSettings") or {}).get("Networks") or {}
        ports = [
            PortBinding(
                private_port=p.get("PrivatePort", 0),
                public_port=p.get("PublicPort"),
                host_ip=p.get("IP"),
                protocol=p.get("Type", "tcp"),
            )
            for p in raw.get("Ports") or []
        ]
        return cls(
            id=raw.get("Id", ""),
            name=name,
            image=raw.get("Image", ""),
            image_id=raw.get("ImageID", ""),
            state=raw.get("State", "running"),
            ports=ports,
            labels=raw.get("Labels") or {},
            networks=sorted(nets),
            network_mode=(raw.get("HostConfig") or {}).get("NetworkMode"),
            ip_addresses=[n.get("IPAddress") for n in nets.values() if n.get("IPAddress")],
        )


def _client_for(docker_host: str, timeout: float) -> httpx.Client:
    if docker_host.startswith("unix://"):
        transport = httpx.HTTPTransport(uds=docker_host.removeprefix("unix://"))
        return httpx.Client(transport=transport, base_url="http://docker", timeout=timeout)
    if docker_host.startswith("tcp://"):
        return httpx.Client(
            base_url="http://" + docker_host.removeprefix("tcp://"), timeout=timeout
        )
    if docker_host.startswith(("http://", "https://")):
        return httpx.Client(base_url=docker_host, timeout=timeout)
    raise ValueError(f"unsupported DOCKER_HOST: {docker_host!r}")


class DockerClient:
    """Read-only view of the local Docker daemon."""

    def __init__(
        self,
        docker_host: str = "unix:///var/run/docker.sock",
        timeout: float = 10.0,
        client: httpx.Client | None = None,
    ) -> None:
        self._http = client or _client_for(docker_host, timeout)

    def list_containers(self, include_stopped: bool = False) -> list[ContainerInfo]:
        """Return running (or all) containers."""
        resp = self._http.get("/containers/json", params={"all": "1" if include_stopped else "0"})
        resp.raise_for_status()
        return [ContainerInfo.from_api(c) for c in resp.json()]

    def inspect_image(self, ref: str) -> dict[str, Any]:
        """Return ``/images/{ref}/json`` or an empty dict if the image is unknown."""
        resp = self._http.get(f"/images/{ref}/json")
        if resp.status_code == 404:
            return {}
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()
        return data

    def close(self) -> None:
        """Close the underlying HTTP connection pool."""
        self._http.close()
