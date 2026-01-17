"""
Interactive visualization for security profiles.

This module provides Plotly-based radar chart visualizations for the 4D
security profile. Can generate interactive HTML or static SVG.

Requires the optional 'visualization' dependency:
    pip install trustworthy-core[visualization]
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass


@dataclass
class RadarChartData:
    """Data structure for radar chart visualization."""

    labels: List[str]
    values: List[float]
    max_value: float = 5.0
    title: str = "Security Profile"


def create_radar_chart(
    scores: Dict[str, float],
    title: str = "Security Profile",
    interactive: bool = True,
    size: int = 400,
) -> str:
    """
    Create a radar chart visualization.

    Args:
        scores: Dict with dimension names as keys and scores as values
                e.g., {"Autonomy": 2, "Efficacy": 3, "Goal Complexity": 2, "Generality": 1}
        title: Chart title
        interactive: If True, return HTML; if False, return SVG
        size: Chart size in pixels

    Returns:
        HTML string (interactive) or SVG string (static)

    Raises:
        ImportError: If plotly is not installed
    """
    try:
        import plotly.graph_objects as go
    except ImportError:
        raise ImportError(
            "Plotly is required for visualization. "
            "Install with: pip install trustworthy-core[visualization]"
        )

    categories = list(scores.keys())
    values = list(scores.values())

    # Close the polygon by repeating the first value
    categories_closed = categories + [categories[0]]
    values_closed = values + [values[0]]

    fig = go.Figure(data=go.Scatterpolar(
        r=values_closed,
        theta=categories_closed,
        fill='toself',
        name='Profile',
        line=dict(color='rgb(31, 119, 180)'),
        fillcolor='rgba(31, 119, 180, 0.3)',
    ))

    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 5],
                tickvals=[1, 2, 3, 4, 5],
            ),
        ),
        showlegend=False,
        title=dict(
            text=title,
            x=0.5,
            xanchor='center',
        ),
        width=size,
        height=size,
        margin=dict(l=80, r=80, t=80, b=80),
    )

    if interactive:
        return fig.to_html(include_plotlyjs='cdn', full_html=False)
    else:
        try:
            return fig.to_image(format='svg').decode('utf-8')
        except Exception:
            # Fallback if kaleido not installed
            return generate_svg_fallback(scores, title, size)


def generate_svg_fallback(
    scores: Dict[str, float],
    title: str = "Security Profile",
    size: int = 400,
) -> str:
    """
    Generate a simple SVG radar chart without plotly/kaleido.

    This is a fallback for when plotly's static export isn't available.

    Args:
        scores: Dict with dimension names and scores
        title: Chart title
        size: Chart size in pixels

    Returns:
        SVG string
    """
    import math

    center = size // 2
    max_radius = (size - 100) // 2
    categories = list(scores.keys())
    values = list(scores.values())
    n = len(categories)

    # Calculate points
    points = []
    label_positions = []
    for i, (cat, val) in enumerate(zip(categories, values)):
        angle = (2 * math.pi * i / n) - (math.pi / 2)  # Start from top
        radius = (val / 5.0) * max_radius
        x = center + radius * math.cos(angle)
        y = center + radius * math.sin(angle)
        points.append(f"{x},{y}")

        # Label position (outside the chart)
        label_radius = max_radius + 30
        label_x = center + label_radius * math.cos(angle)
        label_y = center + label_radius * math.sin(angle)
        label_positions.append((label_x, label_y, cat))

    # Build SVG
    svg_parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size} {size}" width="{size}" height="{size}">',
        f'<style>',
        f'  .label {{ font-family: Arial, sans-serif; font-size: 12px; fill: #333; }}',
        f'  .title {{ font-family: Arial, sans-serif; font-size: 16px; font-weight: bold; fill: #333; }}',
        f'  .grid {{ stroke: #ddd; stroke-width: 1; fill: none; }}',
        f'  .axis {{ stroke: #ccc; stroke-width: 1; }}',
        f'  .data {{ fill: rgba(31, 119, 180, 0.3); stroke: rgb(31, 119, 180); stroke-width: 2; }}',
        f'</style>',
        f'<text x="{center}" y="30" class="title" text-anchor="middle">{title}</text>',
    ]

    # Draw grid circles
    for level in [1, 2, 3, 4, 5]:
        r = (level / 5.0) * max_radius
        svg_parts.append(f'<circle cx="{center}" cy="{center}" r="{r}" class="grid"/>')

    # Draw axis lines
    for i in range(n):
        angle = (2 * math.pi * i / n) - (math.pi / 2)
        end_x = center + max_radius * math.cos(angle)
        end_y = center + max_radius * math.sin(angle)
        svg_parts.append(f'<line x1="{center}" y1="{center}" x2="{end_x}" y2="{end_y}" class="axis"/>')

    # Draw data polygon
    points_str = " ".join(points)
    svg_parts.append(f'<polygon points="{points_str}" class="data"/>')

    # Draw data points
    for point in points:
        x, y = point.split(",")
        svg_parts.append(f'<circle cx="{x}" cy="{y}" r="4" fill="rgb(31, 119, 180)"/>')

    # Draw labels
    for x, y, label in label_positions:
        anchor = "middle"
        if x < center - 10:
            anchor = "end"
        elif x > center + 10:
            anchor = "start"
        svg_parts.append(f'<text x="{x}" y="{y}" class="label" text-anchor="{anchor}">{label}</text>')

    svg_parts.append('</svg>')

    return "\n".join(svg_parts)


def create_comparison_chart(
    profiles: Dict[str, Dict[str, float]],
    title: str = "Profile Comparison",
    interactive: bool = True,
) -> str:
    """
    Create a radar chart comparing multiple profiles.

    Args:
        profiles: Dict mapping profile names to their scores
                  e.g., {"Before": {...}, "After": {...}}
        title: Chart title
        interactive: If True, return HTML; if False, return SVG

    Returns:
        HTML or SVG string
    """
    try:
        import plotly.graph_objects as go
    except ImportError:
        raise ImportError(
            "Plotly is required for visualization. "
            "Install with: pip install trustworthy-core[visualization]"
        )

    fig = go.Figure()

    colors = [
        'rgb(31, 119, 180)',
        'rgb(255, 127, 14)',
        'rgb(44, 160, 44)',
        'rgb(214, 39, 40)',
    ]

    for i, (name, scores) in enumerate(profiles.items()):
        categories = list(scores.keys())
        values = list(scores.values())

        # Close the polygon
        categories_closed = categories + [categories[0]]
        values_closed = values + [values[0]]

        color = colors[i % len(colors)]

        fig.add_trace(go.Scatterpolar(
            r=values_closed,
            theta=categories_closed,
            fill='toself',
            name=name,
            line=dict(color=color),
            fillcolor=color.replace('rgb', 'rgba').replace(')', ', 0.2)'),
        ))

    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 5],
            ),
        ),
        showlegend=True,
        title=title,
    )

    if interactive:
        return fig.to_html(include_plotlyjs='cdn', full_html=False)
    else:
        return fig.to_image(format='svg').decode('utf-8')


def scores_from_rubric(rubric: Any) -> Dict[str, float]:
    """
    Extract scores from a Rubric object for visualization.

    Args:
        rubric: A Rubric object from trustworthy_core.rubric

    Returns:
        Dict with dimension names and numeric scores
    """
    return {
        "Autonomy": rubric.autonomy.score.numeric,
        "Efficacy": rubric.efficacy.score.numeric,
        "Goal Complexity": rubric.goal_complexity.score.numeric,
        "Generality": rubric.generality.score.numeric,
    }
