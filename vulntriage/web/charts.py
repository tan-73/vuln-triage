"""Server-side geometry for small, single-series SVG line charts (no JS chart library)."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime


def compact(value: float) -> str:
    """1234 -> '1.2K', 12000 -> '12K', 950 -> '950'."""
    if abs(value) >= 1000:
        text = f"{value / 1000:.1f}".rstrip("0").rstrip(".")
        return f"{text}K"
    return f"{value:.0f}"


def nice_ceiling(value: float) -> float:
    """Round up to 1, 2, 2.5 or 5 x 10^n so axis ticks are clean numbers."""
    if value <= 0:
        return 1.0
    exp = math.floor(math.log10(value))
    for step in (1, 2, 2.5, 5, 10):
        candidate = step * 10**exp
        if candidate >= value:
            return float(candidate)
    return float(10 ** (exp + 1))


@dataclass
class ChartPoint:
    """One plotted point with pixel position and display strings."""

    x: float
    y: float
    value: float
    label: str
    value_text: str


@dataclass
class LineChart:
    """Everything the template needs to draw one chart."""

    title: str
    width: int
    height: int
    pad_left: int
    pad_bottom: int
    points: list[ChartPoint]
    path: str
    area: str
    y_ticks: list[tuple[float, str]]
    x_labels: list[tuple[float, str]]
    last: ChartPoint | None

    @property
    def empty(self) -> bool:
        """True when there is nothing to draw."""
        return not self.points


def line_chart(
    title: str,
    series: list[tuple[datetime, float]],
    width: int = 360,
    height: int = 140,
) -> LineChart:
    """Lay out a single-series line chart: one y-axis starting at zero, 3 ticks."""
    pad_left, pad_right, pad_top, pad_bottom = 40, 16, 12, 22
    plot_w = width - pad_left - pad_right
    plot_h = height - pad_top - pad_bottom
    top = nice_ceiling(max((v for _, v in series), default=0) * 1.05)
    n = len(series)
    points: list[ChartPoint] = []
    for i, (when, value) in enumerate(series):
        x = pad_left + (plot_w * i / (n - 1) if n > 1 else plot_w / 2)
        y = pad_top + plot_h * (1 - value / top)
        points.append(
            ChartPoint(round(x, 1), round(y, 1), value, when.strftime("%b %d"), f"{value:,.0f}")
        )
    path = " ".join(f"{'M' if i == 0 else 'L'}{p.x},{p.y}" for i, p in enumerate(points))
    base_y = pad_top + plot_h
    area = f"{path} L{points[-1].x},{base_y} L{points[0].x},{base_y} Z" if points else ""
    ticks = [(round(pad_top + plot_h * (1 - f), 1), compact(top * f)) for f in (0, 0.5, 1)]
    x_labels = []
    if points:
        x_labels.append((points[0].x, points[0].label))
        if n > 1:
            x_labels.append((points[-1].x, points[-1].label))
    return LineChart(
        title, width, height, pad_left, pad_bottom, points, path, area, ticks, x_labels,
        points[-1] if points else None,
    )  # fmt: skip
