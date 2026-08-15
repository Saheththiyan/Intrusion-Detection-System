"""
Turns a Suricata eve.json log into a small number of "alert groups" ready
for LLM explanation.

Why grouping: Suricata fires one alert event per matching packet, so the
same signature/src/dest triggers over and over during one conversation
(561 raw alerts in a short pcap is typical). Explaining each one
individually would be slow, expensive, and repetitive to read -- real SOC
tooling aggregates identical alerts the same way. We group by
(signature_id, src_ip, dest_ip, dest_port) and explain the group once.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class AlertGroup:
    signature_id: int
    signature: str
    category: str
    suricata_severity: int
    src_ip: str
    dest_ip: str
    dest_port: int
    proto: str
    app_proto: str | None
    count: int = 0
    first_seen: str | None = None
    last_seen: str | None = None
    dest_hostname: str | None = None
    sample_events: list[dict] = field(default_factory=list)

    @property
    def group_key(self) -> str:
        return f"{self.signature_id}:{self.src_ip}:{self.dest_ip}:{self.dest_port}"


def _build_dns_cache(eve_path: str) -> dict[str, str]:
    """Map IP -> hostname from DNS answers seen in the capture (best effort)."""
    ip_to_host: dict[str, str] = {}
    with open(eve_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            if event.get("event_type") != "dns":
                continue
            dns = event.get("dns", {})
            if dns.get("type") != "answer":
                continue
            rrname = dns.get("rrname")
            for answer in dns.get("answers", []):
                rdata = answer.get("rdata")
                if rdata and rrname:
                    ip_to_host[rdata] = rrname
    return ip_to_host


def load_alert_groups(eve_path: str, samples_per_group: int = 2) -> list[AlertGroup]:
    """Read eve.json and return one AlertGroup per unique (signature, src, dest)."""
    dns_cache = _build_dns_cache(eve_path)
    groups: dict[str, AlertGroup] = {}

    with open(eve_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            if event.get("event_type") != "alert":
                continue

            alert = event["alert"]
            key = f"{alert['signature_id']}:{event.get('src_ip')}:{event.get('dest_ip')}:{event.get('dest_port')}"

            group = groups.get(key)
            if group is None:
                group = AlertGroup(
                    signature_id=alert["signature_id"],
                    signature=alert["signature"],
                    category=alert.get("category", "Unknown"),
                    suricata_severity=alert.get("severity", 3),
                    src_ip=event.get("src_ip"),
                    dest_ip=event.get("dest_ip"),
                    dest_port=event.get("dest_port"),
                    proto=event.get("proto"),
                    app_proto=event.get("app_proto"),
                    dest_hostname=dns_cache.get(event.get("dest_ip")),
                )
                groups[key] = group

            group.count += 1
            ts = event.get("timestamp")
            if group.first_seen is None or ts < group.first_seen:
                group.first_seen = ts
            if group.last_seen is None or ts > group.last_seen:
                group.last_seen = ts
            if len(group.sample_events) < samples_per_group:
                group.sample_events.append(event)

    return sorted(groups.values(), key=lambda g: g.count, reverse=True)
