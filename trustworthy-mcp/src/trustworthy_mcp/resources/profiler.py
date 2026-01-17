"""Security profile resource for MCP.

Exposes security metrics as an MCP resource, inspired by the
Agentic Profiler radar chart visualization from trustworthy-adk.
"""

import json
from dataclasses import dataclass
from typing import Any

from trustworthy_mcp.audit.logger import AuditLogger, SecurityProfile


@dataclass
class RadarChartData:
    """Data structure for radar chart visualization.

    Inspired by trustworthy-adk's radar_chart_tool.py, this provides
    the data needed to render a security posture radar chart.
    """
    labels: list[str]
    values: list[float]
    max_value: float = 1.0
    title: str = "Security Profile"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "labels": self.labels,
            "values": self.values,
            "max_value": self.max_value,
            "title": self.title,
        }

    def to_svg(self, size: int = 400) -> str:
        """Generate a simple SVG radar chart.

        Args:
            size: Size of the SVG in pixels

        Returns:
            SVG string representation
        """
        import math

        center = size // 2
        radius = size // 2 - 40
        n = len(self.labels)

        if n == 0:
            return f'<svg width="{size}" height="{size}"><text x="50%" y="50%" text-anchor="middle">No data</text></svg>'

        # Calculate points for each axis
        angle_step = 2 * math.pi / n
        points = []
        label_positions = []

        for i, (label, value) in enumerate(zip(self.labels, self.values)):
            angle = i * angle_step - math.pi / 2  # Start from top
            # Normalized value (0-1) mapped to radius
            r = (value / self.max_value) * radius
            x = center + r * math.cos(angle)
            y = center + r * math.sin(angle)
            points.append((x, y))

            # Label position (outside the chart)
            label_r = radius + 25
            label_x = center + label_r * math.cos(angle)
            label_y = center + label_r * math.sin(angle)
            label_positions.append((label_x, label_y, label))

        # Build SVG
        svg_parts = [
            f'<svg width="{size}" height="{size}" xmlns="http://www.w3.org/2000/svg">',
            f'<rect width="100%" height="100%" fill="white"/>',
            f'<text x="{center}" y="20" text-anchor="middle" font-size="14" font-weight="bold">{self.title}</text>',
        ]

        # Draw grid circles
        for level in [0.25, 0.5, 0.75, 1.0]:
            r = level * radius
            svg_parts.append(
                f'<circle cx="{center}" cy="{center}" r="{r}" fill="none" stroke="#e0e0e0" stroke-width="1"/>'
            )

        # Draw axis lines
        for i in range(n):
            angle = i * angle_step - math.pi / 2
            x = center + radius * math.cos(angle)
            y = center + radius * math.sin(angle)
            svg_parts.append(
                f'<line x1="{center}" y1="{center}" x2="{x}" y2="{y}" stroke="#e0e0e0" stroke-width="1"/>'
            )

        # Draw data polygon
        if points:
            polygon_points = " ".join(f"{x},{y}" for x, y in points)
            svg_parts.append(
                f'<polygon points="{polygon_points}" fill="rgba(66, 133, 244, 0.3)" stroke="#4285f4" stroke-width="2"/>'
            )

            # Draw data points
            for x, y in points:
                svg_parts.append(
                    f'<circle cx="{x}" cy="{y}" r="4" fill="#4285f4"/>'
                )

        # Draw labels
        for x, y, label in label_positions:
            anchor = "middle"
            if x < center - 10:
                anchor = "end"
            elif x > center + 10:
                anchor = "start"

            svg_parts.append(
                f'<text x="{x}" y="{y}" text-anchor="{anchor}" font-size="11">{label}</text>'
            )

        svg_parts.append('</svg>')
        return "\n".join(svg_parts)


class SecurityProfileResource:
    """MCP resource that exposes security profile data.

    Provides:
    - JSON profile data
    - Radar chart SVG visualization
    - Text summary
    """

    def __init__(self, audit_logger: AuditLogger) -> None:
        """Initialize the resource.

        Args:
            audit_logger: Audit logger to get profile data from
        """
        self.audit_logger = audit_logger

    def get_profile_json(self, window_minutes: int = 60) -> str:
        """Get security profile as JSON.

        Args:
            window_minutes: Time window for metrics

        Returns:
            JSON string with profile data
        """
        profile = self.audit_logger.get_security_profile(window_minutes)
        return json.dumps(profile.to_dict(), indent=2)

    def get_radar_chart_data(self, window_minutes: int = 60) -> RadarChartData:
        """Get radar chart data for visualization.

        Args:
            window_minutes: Time window for metrics

        Returns:
            RadarChartData ready for visualization
        """
        profile = self.audit_logger.get_security_profile(window_minutes)

        # Use the four key scores for the radar chart
        # Note: Some scores are inverted so "higher = better" consistently
        return RadarChartData(
            labels=[
                "Caution",           # Inverted autonomy (lower autonomy = more cautious)
                "Safety",            # Inverted risk exposure
                "Compliance",        # Approval compliance
                "Defense",           # Defense effectiveness
            ],
            values=[
                1.0 - profile.autonomy_score,          # Caution = inverse of autonomy
                1.0 - profile.risk_exposure_score,     # Safety = inverse of risk
                profile.approval_compliance_score,
                profile.defense_effectiveness_score,
            ],
            title=f"Security Profile (last {window_minutes} min)",
        )

    def get_radar_chart_svg(self, window_minutes: int = 60, size: int = 400) -> str:
        """Get radar chart as SVG.

        Args:
            window_minutes: Time window for metrics
            size: SVG size in pixels

        Returns:
            SVG string
        """
        chart_data = self.get_radar_chart_data(window_minutes)
        return chart_data.to_svg(size)

    def get_summary(self, window_minutes: int = 60) -> str:
        """Get human-readable summary.

        Args:
            window_minutes: Time window for metrics

        Returns:
            Text summary
        """
        return self.audit_logger.get_profile_summary(window_minutes)

    def get_all_formats(self, window_minutes: int = 60) -> dict[str, Any]:
        """Get profile in all available formats.

        Args:
            window_minutes: Time window for metrics

        Returns:
            Dictionary with json, svg, and text formats
        """
        return {
            "json": self.get_profile_json(window_minutes),
            "svg": self.get_radar_chart_svg(window_minutes),
            "text": self.get_summary(window_minutes),
            "radar_data": self.get_radar_chart_data(window_minutes).to_dict(),
        }
