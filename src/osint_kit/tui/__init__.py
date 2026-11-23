"""Interactive terminal front end for the toolkit.

``osint-kit`` with no arguments (or ``osint-kit tui``) starts a menu-driven
session: pick a plugin, answer a few questions, read the report, save it.
"""

from osint_kit.tui.app import TuiApp, run
from osint_kit.tui.prompt import Choice, Prompter, RichPrompter

__all__ = ["Choice", "Prompter", "RichPrompter", "TuiApp", "run"]
