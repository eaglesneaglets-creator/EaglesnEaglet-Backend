"""
SVG icon generator for badges.
Each badge gets a unique circular SVG with category colour and tier weight.
Icons are returned as data URIs: data:image/svg+xml,<url-encoded-svg>
"""
from urllib.parse import quote

# Category base colours (hex)
CATEGORY_COLOURS = {
    "learning":    {"bg": "#d1fae5", "fg": "#10b981", "stroke": "#10b981"},
    "assignment":  {"bg": "#fef3c7", "fg": "#f59e0b", "stroke": "#f59e0b"},
    "streak":      {"bg": "#e0f2fe", "fg": "#0ea5e9", "stroke": "#0ea5e9"},
    "points":      {"bg": "#ede9fe", "fg": "#8b5cf6", "stroke": "#8b5cf6"},
    "community":   {"bg": "#ffe4e6", "fg": "#f43f5e", "stroke": "#f43f5e"},
    "quiz":        {"bg": "#cffafe", "fg": "#06b6d4", "stroke": "#06b6d4"},
    "nest":        {"bg": "#ffedd5", "fg": "#f97316", "stroke": "#f97316"},
    "special":     {"bg": "#fef9c3", "fg": "#eab308", "stroke": "#eab308"},
    "elite":       {"bg": "#1e1b4b", "fg": "#fbbf24", "stroke": "#fbbf24"},
}

# Tier visual weight
TIER_STYLES = {
    1: {"stroke_width": 2,  "fill_opacity": 0.15, "has_outer_ring": False, "has_glow": False},
    2: {"stroke_width": 3,  "fill_opacity": 0.4,  "has_outer_ring": False, "has_glow": False},
    3: {"stroke_width": 3,  "fill_opacity": 0.65, "has_outer_ring": True,  "has_glow": False},
    4: {"stroke_width": 4,  "fill_opacity": 0.85, "has_outer_ring": True,  "has_glow": True},
    5: {"stroke_width": 4,  "fill_opacity": 1.0,  "has_outer_ring": True,  "has_glow": True},
}

SYMBOLS = {
    # Learning Journey
    "cracked_shell":    '<ellipse cx="32" cy="36" rx="14" ry="11" fill="none" stroke="{fg}" stroke-width="2"/><path d="M26 30 Q32 20 38 30" fill="none" stroke="{fg}" stroke-width="2"/><path d="M32 20 L30 26 M32 20 L34 26" stroke="{fg}" stroke-width="1.5"/>',
    "fledgling":        '<circle cx="32" cy="28" r="7" fill="{fg}" fill-opacity="0.8"/><path d="M20 38 Q26 30 32 35 Q38 30 44 38" fill="{fg}" fill-opacity="0.5" stroke="{fg}" stroke-width="1.5"/>',
    "first_flight":     '<path d="M18 36 Q25 22 32 28 Q39 22 46 36" fill="none" stroke="{fg}" stroke-width="2.5"/><circle cx="32" cy="28" r="4" fill="{fg}"/>',
    "gliding":          '<path d="M12 32 Q22 22 32 28 Q42 22 52 32" fill="none" stroke="{fg}" stroke-width="3"/><path d="M28 28 L32 36 L36 28" fill="{fg}" fill-opacity="0.6"/>',
    "full_wingspan":    '<path d="M8 32 Q20 18 32 26 Q44 18 56 32" fill="{fg}" fill-opacity="0.3" stroke="{fg}" stroke-width="2.5"/><circle cx="32" cy="30" r="5" fill="{fg}"/>',
    # Assignment Mastery
    "eager_talons":     '<path d="M32 18 L28 30 L24 34 M32 18 L36 30 L40 34" fill="none" stroke="{fg}" stroke-width="2.5" stroke-linecap="round"/>',
    "sharp_claws":      '<path d="M22 18 L18 30 L14 34 M32 16 L30 30 L28 36 M42 18 L46 30 L50 34" fill="none" stroke="{fg}" stroke-width="2" stroke-linecap="round"/>',
    "the_hunter":       '<path d="M32 14 L32 36 M32 14 L20 24 M32 14 L44 24" fill="none" stroke="{fg}" stroke-width="2.5" stroke-linecap="round"/><circle cx="32" cy="38" r="3" fill="{fg}"/>',
    "precision_strike": '<path d="M32 14 L32 38" stroke="{fg}" stroke-width="3" stroke-linecap="round"/><path d="M32 14 L22 22 L32 20 L42 22 Z" fill="{fg}"/><rect x="28" y="34" width="8" height="6" rx="1" fill="{fg}" fill-opacity="0.7"/>',
    "eagle_eyed_assign":'<ellipse cx="32" cy="32" rx="14" ry="9" fill="none" stroke="{fg}" stroke-width="2"/><circle cx="32" cy="32" r="5" fill="{fg}"/><circle cx="32" cy="32" r="2" fill="white"/>',
    # Streak
    "morning_wing":     '<circle cx="32" cy="38" r="6" fill="{fg}" fill-opacity="0.8"/><path d="M32 30 L32 18 M24 32 L14 28 M40 32 L50 28" stroke="{fg}" stroke-width="2" stroke-linecap="round"/><path d="M18 26 Q26 20 32 22 Q38 20 46 26" fill="none" stroke="{fg}" stroke-width="1.5"/>',
    "thermal_rider":    '<path d="M20 36 Q26 24 32 28 Q38 24 44 36" fill="none" stroke="{fg}" stroke-width="2.5"/><path d="M26 42 Q32 36 38 42" fill="none" stroke="{fg}" stroke-width="1.5"/><path d="M28 30 Q32 24 36 30" fill="none" stroke="{fg}" stroke-width="1.5"/>',
    "wind_walker":      '<path d="M14 28 Q22 20 30 26 Q38 20 46 28" fill="none" stroke="{fg}" stroke-width="2"/><path d="M18 34 Q26 26 32 32 Q38 26 46 34" fill="none" stroke="{fg}" stroke-width="2"/><circle cx="32" cy="34" r="4" fill="{fg}" fill-opacity="0.7"/>',
    "sky_drifter":      '<ellipse cx="32" cy="30" rx="16" ry="8" fill="{fg}" fill-opacity="0.15" stroke="{fg}" stroke-width="1.5"/><path d="M20 30 Q26 22 32 26 Q38 22 44 30" fill="none" stroke="{fg}" stroke-width="3"/><circle cx="32" cy="30" r="3" fill="{fg}"/>',
    "eternal_soarer":   '<path d="M16 32 Q24 20 32 28 Q40 20 48 32 Q40 44 32 36 Q24 44 16 32 Z" fill="none" stroke="{fg}" stroke-width="2"/><circle cx="32" cy="32" r="5" fill="{fg}"/>',
    # Points
    "hatchling":        '<circle cx="32" cy="32" r="10" fill="{fg}" fill-opacity="0.8"/><path d="M29 28 Q32 24 35 28" fill="none" stroke="white" stroke-width="1.5"/><circle cx="32" cy="34" r="2" fill="white"/>',
    "nestling":         '<path d="M18 38 Q22 28 32 26 Q42 28 46 38" fill="{fg}" fill-opacity="0.3" stroke="{fg}" stroke-width="2"/><circle cx="32" cy="26" r="7" fill="{fg}" fill-opacity="0.8"/><path d="M30 22 Q32 18 34 22" fill="none" stroke="white" stroke-width="1.5"/>',
    "fledge":           '<path d="M22 38 Q26 28 32 24 Q38 28 42 38" fill="none" stroke="{fg}" stroke-width="2"/><path d="M22 30 Q32 20 42 30" fill="{fg}" fill-opacity="0.4" stroke="{fg}" stroke-width="2"/><circle cx="32" cy="24" r="5" fill="{fg}"/>',
    "talon_bearer":     '<path d="M32 16 L28 28 L24 32 M32 16 L36 28 L40 32" stroke="{fg}" stroke-width="3" stroke-linecap="round" fill="none"/><rect x="26" y="32" width="12" height="4" rx="2" fill="{fg}"/><path d="M26 36 L24 42 M32 36 L32 42 M38 36 L40 42" stroke="{fg}" stroke-width="2" stroke-linecap="round"/>',
    "sky_sovereign":    '<polygon points="32,14 36,26 48,26 38,34 42,46 32,38 22,46 26,34 16,26 28,26" fill="{fg}" fill-opacity="0.9" stroke="{fg}" stroke-width="1"/>',
    # Community Voice
    "first_chirp":      '<circle cx="28" cy="28" r="8" fill="{fg}" fill-opacity="0.7"/><path d="M22 28 L18 36 L28 32 Z" fill="{fg}" fill-opacity="0.7"/><rect x="36" y="22" width="12" height="8" rx="4" fill="{fg}" fill-opacity="0.5"/><path d="M38 34 L36 38" stroke="{fg}" stroke-width="2" stroke-linecap="round"/>',
    "nest_voice":       '<circle cx="28" cy="28" r="8" fill="{fg}" fill-opacity="0.8"/><path d="M22 28 L18 36 L28 32 Z" fill="{fg}" fill-opacity="0.8"/><path d="M38 22 Q44 28 38 34" fill="none" stroke="{fg}" stroke-width="2" stroke-linecap="round"/><path d="M42 18 Q52 28 42 38" fill="none" stroke="{fg}" stroke-width="1.5" stroke-linecap="round"/>',
    "flock_caller":     '<circle cx="26" cy="30" r="7" fill="{fg}" fill-opacity="0.8"/><path d="M20 30 L16 38 L26 34 Z" fill="{fg}"/><path d="M36 20 Q46 28 36 36" fill="none" stroke="{fg}" stroke-width="2.5" stroke-linecap="round"/><path d="M40 16 Q54 28 40 40" fill="none" stroke="{fg}" stroke-width="1.5" stroke-linecap="round"/>',
    "eagle_call":       '<circle cx="24" cy="30" r="8" fill="{fg}"/><path d="M18 30 L14 38 L24 34 Z" fill="{fg}"/><rect x="34" y="24" width="16" height="12" rx="3" fill="{fg}" fill-opacity="0.6"/><path d="M50 26 L54 22 M50 30 L56 30 M50 34 L54 38" stroke="{fg}" stroke-width="1.5" stroke-linecap="round"/>',
    "echo_of_sky":      '<circle cx="32" cy="28" r="6" fill="{fg}"/><path d="M26 28 L22 36 L32 32 Z" fill="{fg}"/><circle cx="32" cy="28" r="12" fill="none" stroke="{fg}" stroke-width="1.5" opacity="0.6"/><circle cx="32" cy="28" r="18" fill="none" stroke="{fg}" stroke-width="1" opacity="0.3"/>',
    # Quiz
    "keen_eye":         '<ellipse cx="32" cy="32" rx="16" ry="10" fill="none" stroke="{fg}" stroke-width="2"/><circle cx="32" cy="32" r="5" fill="{fg}"/><circle cx="32" cy="32" r="2" fill="white"/>',
    "focused_gaze":     '<ellipse cx="32" cy="32" rx="16" ry="10" fill="none" stroke="{fg}" stroke-width="2.5"/><circle cx="32" cy="32" r="6" fill="{fg}"/><circle cx="32" cy="32" r="2.5" fill="white"/><path d="M14 26 L18 28 M14 38 L18 36 M50 26 L46 28 M50 38 L46 36" stroke="{fg}" stroke-width="1.5" stroke-linecap="round"/>',
    "sharp_sight":      '<ellipse cx="32" cy="32" rx="16" ry="10" fill="none" stroke="{fg}" stroke-width="2.5"/><circle cx="32" cy="32" r="7" fill="{fg}"/><circle cx="32" cy="32" r="3" fill="white"/><line x1="32" y1="14" x2="32" y2="50" stroke="{fg}" stroke-width="1" opacity="0.4"/><line x1="14" y1="32" x2="50" y2="32" stroke="{fg}" stroke-width="1" opacity="0.4"/>',
    "predators_vision": '<ellipse cx="22" cy="32" rx="10" ry="7" fill="none" stroke="{fg}" stroke-width="2"/><circle cx="22" cy="32" r="4" fill="{fg}"/><ellipse cx="42" cy="32" rx="10" ry="7" fill="none" stroke="{fg}" stroke-width="2"/><circle cx="42" cy="32" r="4" fill="{fg}"/><circle cx="22" cy="32" r="1.5" fill="white"/><circle cx="42" cy="32" r="1.5" fill="white"/>',
    "raptor_mind":      '<ellipse cx="32" cy="26" rx="12" ry="9" fill="{fg}" fill-opacity="0.7"/><path d="M22 30 Q18 36 22 40 Q26 44 32 42 Q38 44 42 40 Q46 36 42 30" fill="{fg}" fill-opacity="0.5"/><path d="M20 26 Q18 18 26 18 M44 26 Q46 18 38 18" fill="none" stroke="{fg}" stroke-width="2"/>',
    # Nest Presence
    "flock_joiner":     '<circle cx="24" cy="30" r="7" fill="{fg}" fill-opacity="0.7"/><circle cx="40" cy="30" r="7" fill="{fg}" fill-opacity="0.7"/><path d="M18 40 Q24 34 32 38 Q40 34 46 40" fill="none" stroke="{fg}" stroke-width="2"/>',
    "nest_regular":     '<path d="M16 36 Q24 24 32 28 Q40 24 48 36" fill="{fg}" fill-opacity="0.3" stroke="{fg}" stroke-width="2"/><circle cx="32" cy="28" r="6" fill="{fg}" fill-opacity="0.8"/><path d="M28 36 L28 44 L36 44 L36 36" fill="{fg}" fill-opacity="0.5" stroke="{fg}" stroke-width="1.5"/>',
    "circle_rider":     '<circle cx="32" cy="32" r="14" fill="none" stroke="{fg}" stroke-width="2"/><circle cx="32" cy="18" r="4" fill="{fg}"/><circle cx="44" cy="28" r="3" fill="{fg}" fill-opacity="0.7"/><circle cx="40" cy="42" r="3" fill="{fg}" fill-opacity="0.7"/><circle cx="24" cy="42" r="3" fill="{fg}" fill-opacity="0.7"/><circle cx="20" cy="28" r="3" fill="{fg}" fill-opacity="0.7"/>',
    "flock_elder":      '<circle cx="32" cy="26" r="8" fill="{fg}"/><circle cx="18" cy="36" r="5" fill="{fg}" fill-opacity="0.6"/><circle cx="46" cy="36" r="5" fill="{fg}" fill-opacity="0.6"/><circle cx="24" cy="44" r="4" fill="{fg}" fill-opacity="0.4"/><circle cx="40" cy="44" r="4" fill="{fg}" fill-opacity="0.4"/>',
    "sentinel":         '<path d="M32 14 L44 20 L44 34 Q44 42 32 48 Q20 42 20 34 L20 20 Z" fill="{fg}" fill-opacity="0.3" stroke="{fg}" stroke-width="2"/><circle cx="32" cy="30" r="6" fill="{fg}"/><path d="M28 28 L32 22 L36 28" fill="{fg}" fill-opacity="0.8"/>',
    # Special One-Time
    "egg_cracker":      '<ellipse cx="32" cy="34" rx="12" ry="10" fill="{fg}" fill-opacity="0.4" stroke="{fg}" stroke-width="2"/><path d="M26 28 Q32 16 38 28" fill="{fg}" fill-opacity="0.6" stroke="{fg}" stroke-width="2"/><path d="M29 26 L27 30 M32 24 L32 29 M35 26 L37 30" stroke="{fg}" stroke-width="1.5" stroke-linecap="round"/>',
    "found_my_nest":    '<path d="M16 36 Q24 22 32 26 Q40 22 48 36" fill="{fg}" fill-opacity="0.3" stroke="{fg}" stroke-width="2"/><circle cx="32" cy="36" r="5" fill="{fg}"/><path d="M32 30 L32 22 L28 24" fill="none" stroke="{fg}" stroke-width="2" stroke-linecap="round"/>',
    "scout":            '<circle cx="32" cy="30" r="10" fill="none" stroke="{fg}" stroke-width="2.5"/><circle cx="22" cy="30" r="6" fill="{fg}" fill-opacity="0.5"/><circle cx="42" cy="30" r="6" fill="{fg}" fill-opacity="0.5"/><path d="M24 22 L26 20 M40 22 L38 20" stroke="{fg}" stroke-width="2" stroke-linecap="round"/>',
    "resource_eagle":   '<path d="M22 42 L22 22 L42 22 L42 42 Z" fill="{fg}" fill-opacity="0.3" stroke="{fg}" stroke-width="2"/><path d="M26 28 L38 28 M26 33 L38 33 M26 38 L34 38" stroke="{fg}" stroke-width="1.5" stroke-linecap="round"/><path d="M38 14 Q44 20 38 26" fill="none" stroke="{fg}" stroke-width="2"/><path d="M38 14 L36 20 L42 18 Z" fill="{fg}"/>',
    "mentors_mark":     '<path d="M32 14 L36 26 L48 26 L38 34 L42 46 L32 38 L22 46 L26 34 L16 26 L28 26 Z" fill="{fg}" fill-opacity="0.5" stroke="{fg}" stroke-width="1.5"/><path d="M26 28 L30 32 L38 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round"/>',
    "perfect_feathers": '<path d="M20 36 Q26 18 32 22 Q38 18 44 36" fill="{fg}" fill-opacity="0.4" stroke="{fg}" stroke-width="2"/><path d="M24 36 Q28 24 32 26 Q36 24 40 36" fill="{fg}" fill-opacity="0.6" stroke="{fg}" stroke-width="1.5"/><path d="M32 22 L32 44" stroke="{fg}" stroke-width="2" stroke-linecap="round"/>',
    "early_bird":       '<circle cx="28" cy="28" r="7" fill="{fg}" fill-opacity="0.8"/><path d="M22 30 L18 38 L28 34 Z" fill="{fg}" fill-opacity="0.8"/><circle cx="42" cy="24" r="10" fill="none" stroke="{fg}" stroke-width="2"/><path d="M42 18 L42 24 L46 28" fill="none" stroke="{fg}" stroke-width="2" stroke-linecap="round"/>',
    # Elite
    "thunder_wing":     '<path d="M16 28 Q28 16 32 24 Q36 16 48 28" fill="{fg}" fill-opacity="0.5" stroke="{fg}" stroke-width="2.5"/><path d="M36 22 L28 34 L34 34 L26 48 L40 30 L34 30 Z" fill="{fg}"/>',
    "legend_nest":      '<path d="M32 14 L36 24 L48 24 L38 32 L42 44 L32 36 L22 44 L26 32 L16 24 L28 24 Z" fill="{fg}" stroke="{fg}" stroke-width="1"/><path d="M24 28 Q32 20 40 28 Q40 38 32 44 Q24 38 24 28 Z" fill="none" stroke="white" stroke-width="1.5" opacity="0.6"/>',
    "iron_wing":        '<path d="M14 32 Q22 18 32 24 Q42 18 50 32" fill="{fg}" fill-opacity="0.8" stroke="{fg}" stroke-width="3"/><rect x="24" y="32" width="16" height="8" rx="2" fill="{fg}" fill-opacity="0.6"/><path d="M20 40 L28 40 M36 40 L44 40" stroke="{fg}" stroke-width="2" stroke-linecap="round"/>',
    "chosen_eaglet":    '<path d="M22 42 Q26 28 32 22 Q38 28 42 42" fill="{fg}" fill-opacity="0.4" stroke="{fg}" stroke-width="2"/><path d="M32 18 L34 24 L40 24 L35 28 L37 34 L32 30 L27 34 L29 28 L24 24 L30 24 Z" fill="{fg}" stroke="{fg}" stroke-width="0.5"/>',
    "sky_sovereign_el": '<circle cx="32" cy="30" r="14" fill="{fg}" fill-opacity="0.15" stroke="{fg}" stroke-width="1"/><circle cx="32" cy="30" r="10" fill="{fg}" fill-opacity="0.3"/><polygon points="32,18 34,24 40,24 35,28 37,34 32,30 27,34 29,28 24,24 30,24" fill="{fg}"/><path d="M20 44 Q32 38 44 44" fill="none" stroke="{fg}" stroke-width="2"/>',
}


def make_svg(symbol_key: str, category: str, tier: int = 0) -> str:
    """
    Build a 64×64 circular badge SVG.
    tier=0 means a flat single-tier badge (special/elite).
    """
    colours = CATEGORY_COLOURS[category]
    bg, fg, stroke = colours["bg"], colours["fg"], colours["stroke"]

    if tier > 0:
        ts = TIER_STYLES[tier]
        sw = ts["stroke_width"]
        fill_opacity = ts["fill_opacity"]
        outer_ring = ts["has_outer_ring"]
        glow = ts["has_glow"]
    else:
        sw, fill_opacity, outer_ring, glow = 3, 0.9, True, True

    symbol = SYMBOLS.get(symbol_key, "").replace("{fg}", fg)

    glow_filter = ""
    glow_use = ""
    if glow:
        glow_filter = '<filter id="glow"><feGaussianBlur stdDeviation="2" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>'
        glow_use = 'filter="url(#glow)"'

    outer = f'<circle cx="32" cy="32" r="30" fill="none" stroke="{stroke}" stroke-width="1" opacity="0.4"/>' if outer_ring else ""

    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">'
        f'<defs>{glow_filter}</defs>'
        f'<circle cx="32" cy="32" r="28" fill="{bg}" fill-opacity="{fill_opacity}" '
        f'stroke="{stroke}" stroke-width="{sw}" {glow_use}/>'
        f'{outer}'
        f'{symbol}'
        f'</svg>'
    )
    return f"data:image/svg+xml,{quote(svg)}"
