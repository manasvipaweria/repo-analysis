"""
deslint_classifier.py
---------------------
Post-ESLint inline-style finding classifier for the Apni Mandi / Dakiya design system.

Classification categories
-------------------------
EXACT_MIGRATION
    The inline CSS property+value has a verified, visually identical Tailwind utility
    that exists in the standard Tailwind v4 scale AND is consistent with the Apni Mandi
    design system. suggested_migration is set to the exact class.

TOKEN_CONTEXT_REQUIRED
    The inline style references a CSS custom property (var(--token)) that is defined in
    the Apni Mandi design system but has NO verified Tailwind utility equivalent in this
    project. The token must not be approximated. suggested_migration is NOT set.

DYNAMIC_ALLOWED
    The style value depends on a runtime expression (identifier, conditional, template
    literal with expressions, function call). These cannot become static Tailwind classes
    and are correct to remain inline.

TEST_FIXTURE
    The finding originates from a file that is explicitly a test fixture or rule-demo
    component (e.g. TestArbitrary.jsx, *.test.jsx, *.spec.jsx, __tests__/**).
    These are not production UI issues.

UNCATEGORIZED
    The property/value combination cannot be deterministically placed into the above
    categories from source alone. Human review is needed.

Design-system source of truth
------------------------------
Based on dakiya.apnimandi.us/frontend/src/index.css inspection:
- Shadcn/ui standard tokens: --primary, --muted-foreground, --border, --card, etc.
  → Tailwind v4 utilities: text-primary, text-muted-foreground, border-border, etc.
- Custom Apni Mandi tokens: --success, --danger, --text-secondary, --border-color,
  --primary-light, --accent-blue → NO Tailwind utility (not in theme config)
- Spacing: standard Tailwind 4px-grid (no custom scale)
- Typography: standard Tailwind type scale (no custom scale)

DO NOT APPROXIMATE. If the mapping is not in EXACT_PROPERTY_MAP, do not suggest one.
"""

import re
import os
from typing import Optional, Tuple

# ── Known test-fixture filename patterns ─────────────────────────────────────

TEST_FIXTURE_PATTERNS = [
    re.compile(r"TestArbitrary", re.IGNORECASE),
    re.compile(r"\.test\.[jt]sx?$"),
    re.compile(r"\.spec\.[jt]sx?$"),
    re.compile(r"[/\\]__tests__[/\\]"),
]

# ── Verified exact property→value→Tailwind mappings ──────────────────────────
# Only entries here can be suggested. Each key is (cssProperty, cssValue) in
# the normalized form extracted from the source. Values are the Tailwind utility.
#
# Rules for inclusion:
#  1. The CSS value must produce IDENTICAL visual output as the Tailwind class.
#  2. The Tailwind class must exist in Tailwind v4 (no v3-only utilities).
#  3. The mapping must not depend on context (e.g. parent layout, theme override).
#
# Normalized property names are camelCase (as they appear in JSX style objects).
# Normalized values are lowercased string representations.

EXACT_PROPERTY_MAP: dict[tuple[str, str], str] = {
    # ── Display ──────────────────────────────────────────────────────────────
    ("display", "flex"):         "flex",
    ("display", "block"):        "block",
    ("display", "none"):         "hidden",
    ("display", "grid"):         "grid",
    ("display", "inline"):       "inline",
    ("display", "inline-flex"):  "inline-flex",
    ("display", "inline-block"): "inline-block",
    ("display", "contents"):     "contents",

    # ── Flexbox ───────────────────────────────────────────────────────────────
    ("justifyContent", "center"):        "justify-center",
    ("justifyContent", "space-between"): "justify-between",
    ("justifyContent", "space-around"):  "justify-around",
    ("justifyContent", "space-evenly"):  "justify-evenly",
    ("justifyContent", "flex-start"):    "justify-start",
    ("justifyContent", "flex-end"):      "justify-end",
    ("alignItems", "center"):      "items-center",
    ("alignItems", "flex-start"):  "items-start",
    ("alignItems", "flex-end"):    "items-end",
    ("alignItems", "stretch"):     "items-stretch",
    ("alignItems", "baseline"):    "items-baseline",
    ("alignSelf", "center"):       "self-center",
    ("alignSelf", "flex-start"):   "self-start",
    ("alignSelf", "flex-end"):     "self-end",
    ("alignSelf", "stretch"):      "self-stretch",
    ("flexDirection", "row"):            "flex-row",
    ("flexDirection", "column"):         "flex-col",
    ("flexDirection", "row-reverse"):    "flex-row-reverse",
    ("flexDirection", "column-reverse"): "flex-col-reverse",
    ("flexWrap", "wrap"):       "flex-wrap",
    ("flexWrap", "nowrap"):     "flex-nowrap",
    ("flexWrap", "wrap-reverse"): "flex-wrap-reverse",
    ("flexGrow", "1"):  "flex-1",
    ("flexGrow", "0"):  "grow-0",
    ("flexShrink", "0"): "shrink-0",
    ("flexShrink", "1"): "shrink",

    # ── Font weight ───────────────────────────────────────────────────────────
    # Tailwind v4: exact numeric weights.
    ("fontWeight", "100"):    "font-thin",
    ("fontWeight", "200"):    "font-extralight",
    ("fontWeight", "300"):    "font-light",
    ("fontWeight", "400"):    "font-normal",
    ("fontWeight", "normal"): "font-normal",
    ("fontWeight", "500"):    "font-medium",
    ("fontWeight", "600"):    "font-semibold",
    ("fontWeight", "700"):    "font-bold",
    ("fontWeight", "bold"):   "font-bold",
    ("fontWeight", "800"):    "font-extrabold",
    ("fontWeight", "900"):    "font-black",

    # ── Font size — ONLY exact Tailwind v4 step matches ──────────────────────
    # text-xs=12px(0.75rem), text-sm=14px(0.875rem), text-base=16px(1rem),
    # text-lg=18px(1.125rem), text-xl=20px(1.25rem), text-2xl=24px(1.5rem)
    # NOT included: 0.7rem(11.2px), 0.8rem(12.8px), 0.85rem(13.6px), 0.9rem(14.4px)
    # — these are between-step sizes with no exact Tailwind equivalent.
    ("fontSize", "0.75rem"):  "text-xs",
    ("fontSize", "12px"):     "text-xs",
    ("fontSize", "0.875rem"): "text-sm",
    ("fontSize", "14px"):     "text-sm",
    ("fontSize", "1rem"):     "text-base",
    ("fontSize", "16px"):     "text-base",
    ("fontSize", "1.125rem"): "text-lg",
    ("fontSize", "18px"):     "text-lg",
    ("fontSize", "1.25rem"):  "text-xl",
    ("fontSize", "20px"):     "text-xl",
    ("fontSize", "1.5rem"):   "text-2xl",
    ("fontSize", "24px"):     "text-2xl",
    ("fontSize", "1.875rem"): "text-3xl",
    ("fontSize", "30px"):     "text-3xl",
    ("fontSize", "2.25rem"):  "text-4xl",
    ("fontSize", "36px"):     "text-4xl",

    # ── Spacing — only values that land exactly on the 4px Tailwind grid ─────
    # 1 Tailwind unit = 0.25rem = 4px at 16px root.
    # margin / padding / gap:
    ("margin", "0"):          "m-0",
    ("margin", "0px"):        "m-0",
    ("padding", "0"):         "p-0",
    ("padding", "0px"):       "p-0",
    ("marginBottom", "0"):    "mb-0",
    ("marginBottom", "0.25rem"): "mb-1",
    ("marginBottom", "4px"):  "mb-1",
    ("marginBottom", "0.5rem"):  "mb-2",
    ("marginBottom", "8px"):  "mb-2",
    ("marginBottom", "0.75rem"): "mb-3",
    ("marginBottom", "12px"): "mb-3",
    ("marginBottom", "1rem"): "mb-4",
    ("marginBottom", "16px"): "mb-4",
    ("marginBottom", "1.5rem"): "mb-6",
    ("marginBottom", "24px"): "mb-6",
    ("marginTop", "0"):       "mt-0",
    ("marginTop", "0.5rem"):  "mt-2",
    ("marginTop", "1rem"):    "mt-4",
    ("marginTop", "1.5rem"):  "mt-6",
    ("marginRight", "0"):     "mr-0",
    ("marginLeft", "0"):      "ml-0",
    ("paddingTop", "0.5rem"): "pt-2",
    ("paddingTop", "1rem"):   "pt-4",
    ("paddingTop", "1.5rem"): "pt-6",
    ("paddingBottom", "0.5rem"): "pb-2",
    ("paddingBottom", "1rem"): "pb-4",
    ("paddingBottom", "1.5rem"): "pb-6",

    # ── Width / Height ────────────────────────────────────────────────────────
    ("width", "100%"):   "w-full",
    ("width", "auto"):   "w-auto",
    ("height", "100%"):  "h-full",
    ("height", "auto"):  "h-auto",
    ("minWidth", "0"):   "min-w-0",
    ("maxWidth", "none"): "max-w-none",
    ("minHeight", "0"):  "min-h-0",

    # ── Position ─────────────────────────────────────────────────────────────
    ("position", "relative"): "relative",
    ("position", "absolute"): "absolute",
    ("position", "fixed"):    "fixed",
    ("position", "sticky"):   "sticky",
    ("position", "static"):   "static",

    # ── Overflow ─────────────────────────────────────────────────────────────
    ("overflow", "hidden"):  "overflow-hidden",
    ("overflow", "auto"):    "overflow-auto",
    ("overflow", "scroll"):  "overflow-scroll",
    ("overflow", "visible"): "overflow-visible",
    ("overflowY", "auto"):   "overflow-y-auto",
    ("overflowY", "hidden"):  "overflow-y-hidden",
    ("overflowX", "hidden"):  "overflow-x-hidden",

    # ── Opacity ───────────────────────────────────────────────────────────────
    # Tailwind opacity scale: 0, 5, 10, 20, 25, 30, 40, 50, 60, 70, 75, 80, 90, 95, 100
    ("opacity", "0"):    "opacity-0",
    ("opacity", "0.05"): "opacity-5",
    ("opacity", "0.1"):  "opacity-10",
    ("opacity", "0.2"):  "opacity-20",
    ("opacity", "0.25"): "opacity-25",
    ("opacity", "0.3"):  "opacity-30",
    ("opacity", "0.4"):  "opacity-40",
    ("opacity", "0.5"):  "opacity-50",
    ("opacity", "0.6"):  "opacity-60",
    ("opacity", "0.7"):  "opacity-70",
    ("opacity", "0.75"): "opacity-75",
    ("opacity", "0.8"):  "opacity-80",
    ("opacity", "0.9"):  "opacity-90",
    ("opacity", "0.95"): "opacity-95",
    ("opacity", "1"):    "opacity-100",

    # ── Cursor ────────────────────────────────────────────────────────────────
    ("cursor", "pointer"):   "cursor-pointer",
    ("cursor", "default"):   "cursor-default",
    ("cursor", "not-allowed"): "cursor-not-allowed",
    ("cursor", "auto"):      "cursor-auto",
    ("cursor", "text"):      "cursor-text",

    # ── Visibility ────────────────────────────────────────────────────────────
    ("visibility", "hidden"):  "invisible",
    ("visibility", "visible"): "visible",

    # ── Text align ────────────────────────────────────────────────────────────
    ("textAlign", "left"):    "text-left",
    ("textAlign", "center"):  "text-center",
    ("textAlign", "right"):   "text-right",
    ("textAlign", "justify"): "text-justify",

    # ── Pointer events ────────────────────────────────────────────────────────
    ("pointerEvents", "none"): "pointer-events-none",
    ("pointerEvents", "auto"): "pointer-events-auto",

    # ── User select ───────────────────────────────────────────────────────────
    ("userSelect", "none"): "select-none",
    ("userSelect", "all"):  "select-all",
    ("userSelect", "auto"): "select-auto",

    # ── Whitespace ────────────────────────────────────────────────────────────
    ("whiteSpace", "nowrap"):   "whitespace-nowrap",
    ("whiteSpace", "normal"):   "whitespace-normal",
    ("whiteSpace", "pre-wrap"): "whitespace-pre-wrap",
    ("whiteSpace", "pre"):      "whitespace-pre",

    # ── Border ────────────────────────────────────────────────────────────────
    ("border", "none"): "border-0",
    ("outline", "none"): "outline-none",
}

# ── CSS custom property tokens defined in the Apni Mandi design system ───────
# These appear as var(--token) in inline styles. Those with a verified Tailwind
# utility can be classified as EXACT_MIGRATION (colour utilities map to shadcn
# semantic tokens which are wired into Tailwind v4 via @theme inline in index.css).
#
# token → Tailwind utility PREFIX (the full utility depends on the CSS property:
#   color → text-{token}, background → bg-{token}, etc.)

# Tokens that DO have verified Tailwind v4 utilities (shadcn standard, wired in @theme inline):
TOKENS_WITH_TAILWIND_UTILITY = {
    "primary",           # text-primary, bg-primary
    "primary-foreground",
    "secondary",
    "secondary-foreground",
    "muted",
    "muted-foreground",  # text-muted-foreground
    "accent",
    "accent-foreground",
    "destructive",
    "destructive-foreground",
    "background",
    "foreground",
    "card",
    "card-foreground",
    "popover",
    "popover-foreground",
    "border",
    "input",
    "ring",
}

# Tokens that are defined in Apni Mandi CSS but NOT wired as Tailwind utilities:
TOKENS_WITHOUT_TAILWIND_UTILITY = {
    "success", "success-bg",
    "danger", "danger-bg",
    "warning", "warning-bg",
    "text-primary",   # not the same as var(--foreground)
    "text-secondary",
    "accent-blue",
    "border-color",   # rgba value, not a Tailwind color
    "primary-light",
    "bg-app",
    "font-body", "font-display", "font-mono",
    "transition-fast", "transition-normal",
    "radius",
}

# ── Value extraction helpers ─────────────────────────────────────────────────

_LITERAL_PATTERN = re.compile(
    r'''style=\{+\{?\s*([\s\S]{0,1000}?)\s*\}+\}''',
    re.DOTALL
)
_PROP_VALUE_PATTERN = re.compile(
    r'''(\w+)\s*:\s*(?:"([^"]*)"|'([^']*)'|(\d+(?:\.\d+)?))''',
)
_CSS_VAR_PATTERN = re.compile(r"var\(--([a-zA-Z0-9-]+)\)")

# Dynamic value patterns — if ANY property value matches these, the style cannot
# be a static migration candidate.
_DYNAMIC_VALUE_PATTERNS = [
    re.compile(r"`[^`]*\$\{"),       # template literal with expression
    re.compile(r"\bprops\b"),
    re.compile(r"\bstate\b"),
    re.compile(r"\?\s*['\"\w]"),     # ternary
    re.compile(r"\|{2}"),            # logical OR
    re.compile(r"\+\s*['\"\w]"),     # string concatenation
]


def _is_test_fixture(file_path: str) -> bool:
    """Return True if the file path matches a known test-fixture pattern."""
    normalized = file_path.replace("\\", "/")
    return any(p.search(normalized) for p in TEST_FIXTURE_PATTERNS)


def _has_dynamic_values(style_source: str) -> bool:
    """Return True if the style object source contains any dynamic expression."""
    return any(p.search(style_source) for p in _DYNAMIC_VALUE_PATTERNS)


def _extract_css_vars(style_source: str) -> list[str]:
    """Return all CSS custom property names referenced in the style source."""
    return _CSS_VAR_PATTERN.findall(style_source)


def _extract_static_props(style_source: str) -> list[tuple[str, str]]:
    """
    Extract (property, value) pairs from the style source where the value is a
    string or numeric literal. Returns an empty list if any dynamic values are
    present (conservative: if we can't parse it cleanly, don't classify).
    """
    matches = _PROP_VALUE_PATTERN.findall(style_source)
    result = []
    for prop, v_str, v_str2, v_num in matches:
        value = (v_str or v_str2 or v_num).strip()
        if value:
            result.append((prop, value))
    return result


def _read_style_source(file_path: str, line: int, context: int = 8) -> str:
    """Read the source lines around a finding's line to extract the style object."""
    try:
        with open(file_path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        start = max(0, line - 1)
        end = min(len(lines), line + context)
        return "".join(lines[start:end])
    except OSError:
        return ""


# ── Public API ───────────────────────────────────────────────────────────────

class InlineStyleClassification:
    """Classification result for a single no-inline-styles finding."""

    __slots__ = ("category", "suggested_migration", "rationale")

    def __init__(self, category: str, suggested_migration: Optional[str] = None, rationale: str = ""):
        self.category = category                       # one of the four categories above
        self.suggested_migration = suggested_migration  # only set for EXACT_MIGRATION
        self.rationale = rationale                     # human-readable reason


def classify_inline_style(file_path: str, line: int) -> InlineStyleClassification:
    """
    Classify a deslint/no-inline-styles finding at the given file path + line.

    Algorithm
    ---------
    1. If the file is a test fixture → TEST_FIXTURE (short-circuit).
    2. Read source lines around the finding.
    3. If any dynamic expression is found in the style object → DYNAMIC_ALLOWED.
    4. Extract CSS var() references:
       - If ALL vars are in TOKENS_WITH_TAILWIND_UTILITY → attempt EXACT_MIGRATION
         (the caller maps property + var to the utility class).
       - If ANY var is in TOKENS_WITHOUT_TAILWIND_UTILITY → TOKEN_CONTEXT_REQUIRED.
    5. Extract static property/value pairs:
       - For each pair, look up in EXACT_PROPERTY_MAP.
       - If ALL non-empty pairs have exact matches → EXACT_MIGRATION.
       - Otherwise → UNCATEGORIZED.
    """
    if _is_test_fixture(file_path):
        return InlineStyleClassification(
            "TEST_FIXTURE",
            rationale="File matches a known test-fixture pattern and is not a production component."
        )

    style_source = _read_style_source(file_path, line)

    if not style_source:
        return InlineStyleClassification("UNCATEGORIZED", rationale="Could not read source file.")

    # Dynamic check (takes priority over static analysis)
    if _has_dynamic_values(style_source):
        return InlineStyleClassification(
            "DYNAMIC_ALLOWED",
            rationale="Style object contains runtime/computed values that cannot be static Tailwind classes."
        )

    # CSS custom property check
    css_vars = _extract_css_vars(style_source)
    if css_vars:
        has_no_utility = any(v in TOKENS_WITHOUT_TAILWIND_UTILITY for v in css_vars)
        if has_no_utility:
            no_utility_vars = [v for v in css_vars if v in TOKENS_WITHOUT_TAILWIND_UTILITY]
            return InlineStyleClassification(
                "TOKEN_CONTEXT_REQUIRED",
                rationale=(
                    f"Uses Apni Mandi custom token(s) with no verified Tailwind utility: "
                    f"{', '.join('--' + v for v in no_utility_vars)}. "
                    "Manual review required to establish equivalence."
                )
            )
        # All vars are shadcn tokens with Tailwind utilities, but the specific
        # utility (text-/bg-/border-) depends on the CSS property used in the
        # inline style — we need the full context. Classify as UNCATEGORIZED to
        # be conservative rather than guessing.
        return InlineStyleClassification(
            "UNCATEGORIZED",
            rationale=(
                f"References shadcn token(s) {', '.join('--' + v for v in css_vars)} "
                "which have Tailwind utilities, but the exact property context is needed "
                "to determine the correct utility class (text-/bg-/border-/etc.)."
            )
        )

    # Static property/value pairs
    props = _extract_static_props(style_source)
    if not props:
        return InlineStyleClassification(
            "UNCATEGORIZED",
            rationale="Could not extract CSS property/value pairs from source."
        )

    migrations = []
    for prop, value in props:
        key = (prop, value.lower())
        utility = EXACT_PROPERTY_MAP.get(key)
        if utility:
            migrations.append(utility)
        else:
            # At least one property has no verified mapping → can't claim EXACT
            return InlineStyleClassification(
                "UNCATEGORIZED",
                rationale=(
                    f"Property `{prop}: {value!r}` has no verified Tailwind equivalent "
                    "in the Apni Mandi design system. Do not approximate."
                )
            )

    if migrations:
        suggestion = " ".join(migrations)
        return InlineStyleClassification(
            "EXACT_MIGRATION",
            suggested_migration=suggestion,
            rationale=f"All properties have verified Tailwind v4 equivalents: {suggestion}"
        )

    return InlineStyleClassification("UNCATEGORIZED", rationale="No properties matched the verified mapping.")
