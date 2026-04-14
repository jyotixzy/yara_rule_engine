"""Module description: Ye file logging ka behavior control karti hai, normal mode aur verbose mode dono ke liye."""

from __future__ import annotations

import logging


def configure_logging(verbose: bool = False) -> None:
    """Ye logger ka level aur format set karta hai, taaki output readable rahe."""

    # Normal mode me sirf warnings/errors dikhaye jaate hain; verbose me full debug.
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
