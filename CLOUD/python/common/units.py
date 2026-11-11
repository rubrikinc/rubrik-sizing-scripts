"""Size unit conversion matching PowerShell ConvertTo-SizeUnits."""

from __future__ import annotations

_GIB = 1073741824
_GB = 1000000000
GIB_TO_GB = 1.073741824
GIB_TO_TB = 0.001073741824


def size_units(
    value: float,
    prefix: str = "",
    input_unit: str = "bytes",
    gib_precision: int = 4,
    tib_precision: int = 4,
    gb_precision: int = 4,
    tb_precision: int = 4,
) -> dict[str, float]:
    """Return ``{prefix}GiB/TiB/GB/TB`` for a size given in bytes or GiB."""
    unit = input_unit.lower()
    if unit == "bytes":
        gib = value / _GIB
        tib = gib / 1024
        gb = value / _GB
        tb = gb / 1000
    elif unit == "gib":
        gib = value
        tib = value / 1024
        gb = value * GIB_TO_GB
        tb = value * GIB_TO_TB
    else:
        raise ValueError(f"input_unit must be 'bytes' or 'gib', got {input_unit!r}")
    return {
        f"{prefix}GiB": round(gib, gib_precision),
        f"{prefix}TiB": round(tib, tib_precision),
        f"{prefix}GB": round(gb, gb_precision),
        f"{prefix}TB": round(tb, tb_precision),
    }


def gcp_decimal_units(size_gb: float, prefix: str = "") -> dict[str, float]:
    """GCP reports decimal units: TB is GB / 1000."""
    return {f"{prefix}GB": size_gb, f"{prefix}TB": round(size_gb / 1000, 4)}
