# -*- coding: utf-8 -*-

"""
httpbin.redirect_targets
~~~~~~~~~~~~~~~~~~~~~~~~

Decides whether /redirect-to may send a client to a target: internal
addresses and hosts, other schemes and malformed targets are refused.
"""

import ipaddress
import re
from urllib.parse import urlsplit

# Names that resolve to internal addresses, by convention (.localhost,
# .internal) or because they are wildcard-DNS services that embed an IP in the
# name.
BLOCKED_HOST_SUFFIXES = (
    "localhost", "internal", "local", "localdomain",
    "nip.io", "sslip.io", "xip.io", "localtest.me", "lvh.me",
)

BLOCKED_HOST_NAMES = frozenset(["metadata", "instance-data"])

INTERNAL_NETWORKS = tuple(ipaddress.ip_network(network) for network in (
    # IPv4: loopback, private, link-local, multicast, "this network",
    # carrier-grade NAT, IETF protocol assignments, benchmarking, reserved
    # (which includes the broadcast address)
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "169.254.0.0/16", "224.0.0.0/4", "0.0.0.0/8", "100.64.0.0/10",
    "192.0.0.0/24", "198.18.0.0/15", "240.0.0.0/4",
    # IPv6: loopback, unspecified, unique local, link-local, multicast,
    # site-local (deprecated but still routed by some stacks), local-use NAT64
    "::1/128", "::/128", "fc00::/7", "fe80::/10", "ff00::/8", "fec0::/10",
    "64:ff9b:1::/48",
))

# IPv6 ranges whose last 32 bits are the IPv4 address the traffic reaches:
# NAT64, and IPv4-compatible addresses (deprecated, but [::127.0.0.1] parses).
EMBEDDED_IPV4_NETWORKS = tuple(ipaddress.ip_network(network) for network in (
    "64:ff9b::/96", "::/96",
))

SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")
BAD_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def is_url(target):
    """Return true if target parses as a URL, by the rules Go applies."""
    try:
        parts = urlsplit(target)
    except ValueError:
        return False
    if BAD_ESCAPE.search(target):
        return False
    port = parts.netloc.rpartition("@")[2].rpartition("]")[2].partition(":")[2]
    if port and not port.isdigit():
        return False
    # a relative reference such as "a:b" is neither a scheme nor a path
    return bool(SCHEME.match(target)) or ":" not in target.split("/", 1)[0]


def unsafe_redirect_target(target):
    """Return why target must not be used as a redirect target, or None."""
    if any(c < " " or c in "\x7f\\ " for c in target):
        return "redirect target contains a control character, space or backslash"
    if not is_url(target):
        return "invalid redirect target"
    match = SCHEME.match(target)
    scheme = match.group(1).lower() if match else ""
    if scheme not in ("", "http", "https"):
        return "only http and https redirect targets are allowed"
    rest = target[match.end():] if match else target
    if scheme and not rest.startswith("/"):
        # A target with a scheme but no "//" has no host that can be checked.
        return "redirect target must use //host form"
    netloc = urlsplit(target).netloc if rest.startswith("//") else ""
    host_and_port = netloc.rpartition("@")[2]
    if not host_and_port and (scheme or target.startswith("//")):
        # Browsers take the first path segment as the host here.
        return "redirect target has a scheme or // but no host"
    if any(c > "~" or c == "%" for c in host_and_port):
        # Browsers normalise fullwidth digits and decode escapes, so only
        # plain ASCII hosts can be checked reliably.
        return "redirect target host must be plain ASCII (use punycode)"
    host = (urlsplit(target).hostname or "") if host_and_port else ""
    if host.endswith("."):
        host = host[:-1]
    if not host:
        return None
    if internal_host_name(host):
        return "redirect target is an internal host name"
    address = parse_host_address(host)
    if address is not None and internal_address(address):
        return "redirect target is an internal address"
    return None


def parse_allowed_domains(value):
    """Split a comma-separated ALLOWED_REDIRECT_DOMAINS value."""
    return frozenset(
        domain.strip() for domain in (value or "").split(",") if domain.strip()
    )


def redirect_allowed(target, allowed_domains):
    """With an allowlist, an absolute target's host must be on it. Every
    target must be absolute or root-relative, so "get" or "?x=1" never
    redirect."""
    parts = urlsplit(target)
    host = parts.netloc.rpartition("@")[2]
    if host.startswith("["):
        host = host[1:].partition("]")[0]
    else:
        host = host.partition(":")[0]
    if allowed_domains and host:
        return host in allowed_domains
    return bool(parts.scheme) or parts.path.startswith("/")


def forbidden_redirect_message(allowed_domains):
    """The 403 body for a target the allowlist refuses."""
    if not allowed_domains:
        return ""
    return (
        "Forbidden redirect URL. Please be careful with this link.\n\n"
        "Allowed redirect destinations:\n"
        + "\n".join(sorted("- " + domain for domain in allowed_domains))
    )


def internal_host_name(host):
    if host in BLOCKED_HOST_NAMES:
        return True
    return any(
        host == suffix or host.endswith("." + suffix)
        for suffix in BLOCKED_HOST_SUFFIXES
    )


def parse_host_address(host):
    """Parse an IP literal in every form clients accept, including inet_aton
    shorthand: decimal (2852039166), hex (0xa9fea9fe), octal
    (0251.0376.0251.0376) and fewer than four parts (127.1)."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return parse_loose_ipv4(host)


def parse_loose_ipv4(host):
    parts = host.split(".")
    if len(parts) > 4:
        return None
    values = []
    for part in parts:
        if part.lower() == "0x":
            part = "0"  # browsers read a bare 0x octet as zero: 127.0x.0.1
        value = parse_c_number(part)
        if value is None:
            return None
        values.append(value)
    last = len(values) - 1
    number = 0
    for i, value in enumerate(values[:last]):
        if value > 0xFF:
            return None
        number |= value << (24 - 8 * i)
    if values[last] >= 1 << (32 - 8 * last):
        return None
    return ipaddress.IPv4Address(number | values[last])


def parse_c_number(text):
    """Parse an unsigned 32-bit number as C and Go do: a 0x hex, 0o octal or
    0b binary prefix, a leading 0 for octal, otherwise decimal, with
    underscores allowed between digits. Returns None if text is not one."""
    if not text or not underscores_ok(text):
        return None
    digits, base = text, 10
    if text[0] == "0":
        prefix = text[1:2].lower()
        if len(text) >= 3 and prefix in ("b", "o", "x"):
            digits, base = text[2:], {"b": 2, "o": 8, "x": 16}[prefix]
        else:
            digits, base = text[1:], 8
    digits = digits.replace("_", "")
    if not digits:
        return 0  # text was "0"
    if any(c not in "0123456789abcdef"[:base] for c in digits.lower()):
        return None
    value = int(digits, base)
    return value if value <= 0xFFFFFFFF else None


def underscores_ok(text):
    """Underscores must sit between digits, or after a base prefix."""
    if "_" not in text:
        return True
    saw, i = "^", 0
    is_hex = False
    if len(text) >= 2 and text[0] == "0" and text[1].lower() in "box":
        i, saw, is_hex = 2, "0", text[1].lower() == "x"
    for c in text[i:]:
        if c.isdigit() or (is_hex and c.lower() in "abcdef"):
            saw = "0"
        elif c == "_":
            if saw != "0":
                return False
            saw = "_"
        elif saw == "_":
            return False
        else:
            saw = "!"
    return saw != "_"


def internal_address(address):
    if address.version == 6:
        if address.ipv4_mapped is not None:
            address = address.ipv4_mapped
        else:
            for network in EMBEDDED_IPV4_NETWORKS:
                if address in network:
                    address = ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
                    break
    return any(
        address.version == network.version and address in network
        for network in INTERNAL_NETWORKS
    )
