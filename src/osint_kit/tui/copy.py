"""Plain-language wording for the interactive flow.

Fields are generated from each plugin's parser; this module only replaces the
terse flag names with questions, and marks the few optional inputs that belong
in the main flow rather than under "advanced".
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field


@dataclass(frozen=True)
class FieldCopy:
    """Wording for one input."""

    label: str
    hint: str = ""
    primary: bool = False
    example: str = ""


@dataclass(frozen=True)
class GroupCopy:
    """Wording for a mutually exclusive group of inputs."""

    question: str
    skip_label: str = "Neither"


@dataclass(frozen=True)
class PluginCopy:
    """Wording for one plugin's screen."""

    tagline: str
    fields: Mapping[str, FieldCopy] = field(default_factory=dict)
    groups: Mapping[str, GroupCopy] = field(default_factory=dict)
    example: tuple[str, ...] = ()


PLUGIN_COPY: Mapping[str, PluginCopy] = {
    "social_diff": PluginCopy(
        tagline="See who does not follow you back, and who follows you that you do not.",
        fields={
            "followers": FieldCopy(
                "Where are your followers?",
                "The followers_*.html file, or the folder that holds your export.",
                primary=True,
                example="~/Downloads/instagram-export",
            ),
            "following": FieldCopy(
                "And your following list?",
                "following.html, or the same export folder.",
                primary=True,
                example="~/Downloads/instagram-export/following.html",
            ),
            "previous": FieldCopy(
                "Compare against an older export?",
                "Optional. Adds who you gained and who you lost since then.",
                primary=True,
                example="~/Downloads/instagram-export-old",
            ),
            "include_mutuals": FieldCopy(
                "List your mutual follows as well?",
                "Useful on small accounts, very noisy on large ones.",
            ),
        },
        example=("osint-kit social_diff --followers ./export --following ./export/following.html",),
    ),
    "domain_recon": PluginCopy(
        tagline="DNS records, subdomains, and email security for a domain you own.",
        fields={
            "domain": FieldCopy(
                "Which domain?",
                "The bare domain, without https://.",
                primary=True,
                example="example.com",
            ),
            "no_ct": FieldCopy(
                "Skip the certificate-transparency lookup?", "Faster, fewer results."
            ),
            "no_dnssec": FieldCopy("Skip DNSSEC checks?", "Faster, fewer results."),
            "max_subdomains": FieldCopy("Most subdomains to list", "Default is 200."),
        },
        example=("osint-kit domain_recon example.com",),
    ),
    "rdap": PluginCopy(
        tagline="Registration details for a domain or IP address, from public RDAP.",
        fields={
            "target": FieldCopy(
                "Domain or IP address?",
                "Registration data is public; the query goes to rdap.org.",
                primary=True,
                example="example.com",
            ),
            "no_asn": FieldCopy("Skip the ASN lookup for IP addresses?"),
            "max_nameservers": FieldCopy("Most nameservers to list", "Default is 50."),
        },
        example=("osint-kit rdap example.com",),
    ),
    "email_headers": PluginCopy(
        tagline="Trace an email's route and check SPF, DKIM, and DMARC results.",
        fields={
            "headers": FieldCopy(
                "Which file holds the raw headers?",
                "Paste the full header block of the message into a .eml or .txt file.",
                primary=True,
                example="~/mail/message.eml",
            ),
            "no_hop_findings": FieldCopy("Summarise the hop chain instead of listing every hop?"),
        },
        example=("osint-kit email_headers message.eml",),
    ),
    "exif": PluginCopy(
        tagline="Read or remove metadata such as GPS, camera, and timestamps.",
        fields={
            "images": FieldCopy(
                "Which image files?",
                "One or more paths.",
                primary=True,
                example="~/Photos/IMG_1234.jpg",
            ),
            "strip": FieldCopy(
                "Remove the metadata instead of showing it?", "Writes copies, never edits in place."
            ),
            "dest": FieldCopy(
                "Where should the cleaned files go?", "A file for one image, a folder for many."
            ),
        },
        example=("osint-kit exif photo.jpg", "osint-kit exif photo.jpg --strip --dest cleaned.jpg"),
    ),
    "log_analyzer": PluginCopy(
        tagline="Find scanners, bursts, and noisy sources in web or sshd logs.",
        fields={
            "logs": FieldCopy(
                "Which log files?",
                "One or more paths. Use - for stdin.",
                primary=True,
                example="~/logs/access.log",
            ),
            "log_format": FieldCopy(
                "How should the log be read?", "Auto-detection is right unless it guesses wrong."
            ),
            "window": FieldCopy("Burst window in seconds", "Default is 60."),
            "burst_threshold": FieldCopy(
                "Requests per window that count as a burst", "Default is 5."
            ),
            "scan_threshold": FieldCopy(
                "Error paths per source that count as scanning", "Default is 10."
            ),
            "top": FieldCopy("How many top sources to list", "Default is 5."),
        },
        example=("osint-kit log_analyzer access.log",),
    ),
    "hashing": PluginCopy(
        tagline="Hash text or a file, encode and decode, or identify an unknown hash.",
        fields={
            "text": FieldCopy(
                "Text to work on", "Leave empty if you would rather use a file.", primary=True
            ),
            "file": FieldCopy(
                "Or a file to work on", "Leave empty if you already gave text.", primary=True
            ),
            "algorithms": FieldCopy("Hash algorithm", "Default is sha256."),
            "identify": FieldCopy(
                "Identify a hash instead?",
                "Paste an existing hash, for example a 32-character one.",
            ),
            "encode": FieldCopy("Encode the input as", ""),
            "decode": FieldCopy("Decode the input from", ""),
        },
        groups={
            "file|text": GroupCopy("What should it work on?", "Neither"),
            "decode|encode": GroupCopy("Add an encode or decode step?", "No, just hash it"),
        },
        example=(
            "osint-kit hashing --text hello",
            "osint-kit hashing --identify 2cf24dba5fb0a3...",
        ),
    ),
    "username_check": PluginCopy(
        tagline="Check whether a username exists on 20 public sites, one request at a time.",
        fields={
            "username": FieldCopy(
                "Which username?",
                "Letters, digits, dots, and underscores.",
                primary=True,
                example="someusername",
            ),
            "sites": FieldCopy("Limit to one site?", "Default is every allowlisted site."),
            "no_robots": FieldCopy("Ignore robots.txt?", "Not recommended; sites may refuse."),
        },
        example=("osint-kit username_check someusername",),
    ),
}


def field_copy(plugin: str, dest: str) -> FieldCopy:
    """Wording for ``plugin``'s ``dest``, with a readable fallback."""
    return PLUGIN_COPY.get(plugin, PluginCopy(tagline="")).fields.get(
        dest, FieldCopy(dest.replace("_", " ").capitalize())
    )


def tagline(plugin: str) -> str:
    """One line describing what the plugin is for."""
    return PLUGIN_COPY.get(plugin, PluginCopy(tagline="")).tagline


def group_copy(plugin: str, group: str) -> GroupCopy:
    """Wording for a mutually exclusive group, keyed by its member dests."""
    return PLUGIN_COPY.get(plugin, PluginCopy(tagline="")).groups.get(
        group, GroupCopy("Choose one", "None")
    )


__all__ = [
    "PLUGIN_COPY",
    "FieldCopy",
    "GroupCopy",
    "PluginCopy",
    "field_copy",
    "group_copy",
    "tagline",
]
