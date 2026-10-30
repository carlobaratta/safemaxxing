"""pf rule text for Paranoia Mode: default-deny egress inside `com.apple/safemaxxing`.

Pure: every function returns text for `pfctl -a <anchor> -f -`. Darwin's `pfctl -n` parses
without root, so the tests check the exact text against the real grammar on any Mac.

Only outbound traffic is filtered. The main ruleset has no rules of its own after
`anchor "com.apple/*"`, so inbound packets, replies included, pass by default: a grant needs
no state, which is why grants are `no state` and a revoked grant stops the very next packet.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass

from safemaxxing.firewall import ANCHOR, TABLE
from safemaxxing.models import Protocol

GRANTS_ANCHOR_NAME = "grants"
GRANTS_ANCHOR = f"{ANCHOR}/{GRANTS_ANCHOR_NAME}"
# Resolvers the sinkhole forwards to (and, without the sinkhole, the only DNS servers allowed).
DNS_TABLE = "safemaxxing_dns"
NTP_TABLE = "safemaxxing_ntp"
APPLE_TABLE = "safemaxxing_apple"
# Static exceptions the user lists (a VPN endpoint, a corporate proxy).
USER_TABLE = "safemaxxing_user"
# Only root can bind a source port below 1024, so a rule that matches this range cannot be
# ridden by an unprivileged process: the sinkhole sends its upstream queries from here.
SINKHOLE_UPSTREAM_PORTS = (700, 799)
SINKHOLE_PORT = 53
# Apple owns 17.0.0.0/8 outright, and 2620:149::/32 is its ARIN IPv6 block.
APPLE_NETWORKS = ("17.0.0.0/8", "2620:149::/32")
# APNs listens on 5223 and 2197. Its 443 fallback is all of iCloud there, iCloud Drive
# included, a way out for files, so it is opt-in (`apple_443`).
APNS_PORTS = (5223, 2197)
# ICMPv6 that IPv6 cannot work without: router solicitation, neighbour solicitation and
# advertisement (RFC 4861), MLDv2 listener report (RFC 3810).
ICMP6_TYPES = (133, 135, 136, 143)
MDNS_V4 = "224.0.0.251"
MDNS_V6 = "ff02::fb"


@dataclass(frozen=True, slots=True)
class LockdownConfig:
    """What the default-deny ruleset lets through besides grants."""

    # Redirect every outbound :53 query into the local sinkhole (Module 5). Off, DNS may only
    # reach the resolvers in `safemaxxing_dns`, unfiltered.
    sinkhole: bool = True
    apple_443: bool = False


def _ports(ports: Iterable[int]) -> str:
    return "{ " + " ".join(str(p) for p in ports) + " }"


DEFAULT_CONFIG = LockdownConfig()


def lockdown_rules(config: LockdownConfig = DEFAULT_CONFIG) -> str:
    """The anchor's ruleset in Paranoia Mode, translation rules first as pf requires.

    The v0.2 block table still comes first, so an explicit block beats any grant; the last
    rule drops and logs to `pflog0`, which is what the learn loop reads.
    """
    low, high = SINKHOLE_UPSTREAM_PORTS
    apple_ports = (*APNS_PORTS, 443) if config.apple_443 else APNS_PORTS
    lines: list[str] = []
    if config.sinkhole:
        lines += [
            f"rdr pass on lo0 inet proto {{ udp tcp }} from any to any port 53 "
            f"-> 127.0.0.1 port {SINKHOLE_PORT}",
            f"rdr pass on lo0 inet6 proto {{ udp tcp }} from any to any port 53 "
            f"-> ::1 port {SINKHOLE_PORT}",
        ]
    lines += [
        f"block drop out quick from any to <{TABLE}>",
        "pass out quick on lo0 all",
        # DHCP and DHCPv6 clients send from privileged ports: only root (configd) can.
        "pass out quick inet proto udp from any port 68 to any port 67",
        "pass out quick inet6 proto udp from any port 546 to any port 547",
        f"pass out quick inet6 proto ipv6-icmp from any to any icmp6-type {_ports(ICMP6_TYPES)}",
        f"pass out quick inet proto udp from any to {MDNS_V4} port 5353",
        f"pass out quick inet6 proto udp from any to {MDNS_V6} port 5353",
    ]
    if config.sinkhole:
        lines += [
            f"pass out quick proto {{ udp tcp }} from any port {low}:{high} "
            f"to <{DNS_TABLE}> port 53",
            *(
                f"pass out quick route-to lo0 {family} proto {{ udp tcp }} "
                "from any to any port 53 keep state"
                for family in ("inet", "inet6")
            ),
        ]
    else:
        lines.append(f"pass out quick proto {{ udp tcp }} from any to <{DNS_TABLE}> port 53")
    lines += [
        f"pass out quick proto udp from any to <{NTP_TABLE}> port 123",
        f"pass out quick proto tcp from any to <{APPLE_TABLE}> port {_ports(apple_ports)}",
        f"pass out quick from any to <{USER_TABLE}>",
        f'anchor "{GRANTS_ANCHOR_NAME}"',
        "block drop out log quick all",
    ]
    return "\n".join(lines) + "\n"


@dataclass(frozen=True, slots=True, order=True)
class Grant:
    """One destination a leased app may reach: (protocol, address, port).

    The address and port end up in pf rule text, so both are validated here: nothing that
    reaches `pfctl` is a string an app chose.
    """

    protocol: Protocol
    address: str
    port: int

    def __post_init__(self) -> None:
        # psutil spells a link-local peer `fe80::1%en0`, pflog and pktap `fe80::1`: one grant.
        ip = ipaddress.ip_address(self.address.split("%", 1)[0])
        if ip.is_unspecified or ip.is_multicast or ip.is_loopback:
            raise ValueError(f"refusing to grant {ip}")
        if not 0 < self.port < 65536:
            raise ValueError(f"port out of range: {self.port}")
        # Normalised spelling, so two spellings of one address are one grant.
        object.__setattr__(self, "address", str(ip))

    @property
    def family(self) -> str:
        """`inet6` or `inet`."""
        return "inet6" if ":" in self.address else "inet"

    def rule(self) -> str:
        """The pass rule for this grant; stateless, see the module docstring."""
        return (
            f"pass out quick {self.family} proto {self.protocol.value} "
            f"from any to {self.address} port {self.port} no state"
        )


def grant_rules(grants: Iterable[Grant]) -> str:
    """The grants sub-anchor's ruleset: one sorted rule per distinct grant ('' for none)."""
    return "".join(f"{g.rule()}\n" for g in sorted(set(grants)))
