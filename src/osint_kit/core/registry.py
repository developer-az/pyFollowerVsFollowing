"""Plugin discovery: built-ins first, then the ``osint_kit.plugins`` entry group."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from importlib.metadata import EntryPoint, entry_points

from osint_kit.core.plugin import BasePlugin, Plugin

ENTRY_POINT_GROUP = "osint_kit.plugins"


def builtin_plugin_types() -> tuple[type[BasePlugin], ...]:
    """Import and return in-tree plugin classes.

    Imports live here (not at module import time in each plugin) so ``list``
    stays fast and a broken optional dependency cannot take down the CLI.
    """
    from osint_kit.plugins.domain_recon import DomainReconPlugin
    from osint_kit.plugins.email_headers import EmailHeadersPlugin
    from osint_kit.plugins.exif import ExifPlugin
    from osint_kit.plugins.hashing import HashingPlugin
    from osint_kit.plugins.log_analyzer import LogAnalyzerPlugin
    from osint_kit.plugins.rdap import RdapPlugin
    from osint_kit.plugins.social_diff import SocialDiffPlugin
    from osint_kit.plugins.username_check import UsernameCheckPlugin

    return (
        SocialDiffPlugin,
        DomainReconPlugin,
        RdapPlugin,
        EmailHeadersPlugin,
        ExifPlugin,
        LogAnalyzerPlugin,
        HashingPlugin,
        UsernameCheckPlugin,
    )


def _entry_points(group: str) -> Iterable[EntryPoint]:
    return entry_points(group=group)


def load_plugins(
    *,
    include_entry_points: bool = True,
    warn: Callable[[str], None] | None = None,
) -> dict[str, Plugin]:
    """Return ``{name: plugin}`` with built-ins winning name conflicts."""
    plugins: dict[str, Plugin] = {}
    for plugin_type in builtin_plugin_types():
        instance = plugin_type()
        plugins[instance.name] = instance

    if not include_entry_points:
        return plugins

    for entry_point in _entry_points(ENTRY_POINT_GROUP):
        name = entry_point.name
        if name in plugins:
            # A pip-installed osint-kit registers its built-ins as entry points
            # too; skip those quietly, but warn about genuine third-party clashes.
            if not entry_point.value.startswith("osint_kit.plugins.") and warn is not None:
                warn(f"ignoring entry point {name!r}: a built-in plugin already uses that name")
            continue
        try:
            loaded = entry_point.load()
            instance = loaded() if isinstance(loaded, type) else loaded
        except Exception as exc:  # pragma: no cover - depends on third-party packages
            if warn is not None:
                warn(f"could not load entry point {name!r}: {exc}")
            continue
        if not isinstance(instance, Plugin):  # runtime_checkable protocol
            if warn is not None:
                warn(f"entry point {name!r} does not satisfy the plugin protocol")
            continue
        plugins[instance.name] = instance
    return plugins


def by_name(plugins: Mapping[str, Plugin]) -> dict[str, Plugin]:
    """Sorted copy, for stable CLI help."""
    return dict(sorted(plugins.items()))
