from __future__ import annotations

import warnings
from pathlib import Path
from typing import Any

from ..models import ScanLimits
from .common import finding


_MAX_DECODED_PIXELS = 4_000_000


def check_image(
    source: Path,
    path: str,
    limits: ScanLimits,
) -> tuple[list[dict[str, Any]], str | None]:
    try:
        from PIL import Image, UnidentifiedImageError
    except ImportError:
        return [], "image_dependency_unavailable"

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(source) as opened:
                if opened.width * opened.height > _MAX_DECODED_PIXELS:
                    return [], "image_resource_limit_exceeded"
                image = opened.convert("RGBA")
                image.load()
    except (Image.DecompressionBombWarning, Image.DecompressionBombError):
        return [], "image_resource_limit_exceeded"
    except (OSError, ValueError, UnidentifiedImageError):
        return [
            finding(
                "image_parse_failed",
                path,
                {"error_code": "image_parse_failed"},
                evidence_layer="not_checked",
                classification="not_checked",
            )
        ], "image_parse_failed"

    tile_size = limits.tile_size
    if tile_size <= 0 or image.width < tile_size or image.height < tile_size:
        return [], None
    seen: dict[bytes, tuple[int, int]] = {}
    for y in range(0, image.height - tile_size + 1, tile_size):
        for x in range(0, image.width - tile_size + 1, tile_size):
            tile = image.crop((x, y, x + tile_size, y + tile_size)).tobytes()
            previous = seen.get(tile)
            if previous is not None:
                return [
                    finding(
                        "repeated_image_tile",
                        path,
                        {
                            "first_tile": {"x": previous[0], "y": previous[1]},
                            "second_tile": {"x": x, "y": y},
                            "tile_size": tile_size,
                        },
                        evidence_layer="data_show",
                        classification="informational",
                    )
                ], None
            seen[tile] = (x, y)
    return [], None
