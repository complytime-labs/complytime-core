# Evidence Staleness Model

**Date**: 2026-04-26
**Status**: Accepted

## Decision

Evidence staleness is frequency-aware, driven by `Policy.adherence.assessment-plans[].frequency`. The UI communicates staleness through a neutral background tint gradient and an interactive freshness bar.

## Staleness Resolution

| Priority | Condition | Staleness threshold |
|:--|:--|:--|
| 1 | Assessment plan has `frequency` | `age(collected_at) > frequency_to_days(frequency)` |
| 2 | `frequency = on-demand` | Never stale |
| 3 | No assessment plan for this evidence row | Fall back to 30-day default |

### Frequency-to-days mapping

| Frequency | Cycle days |
|:--|:--|
| daily | 1 |
| weekly | 7 |
| monthly | 30 |
| quarterly | 90 |
| annually | 365 |
| on-demand | N/A (never stale) |

## Freshness Buckets

| Bucket | Condition | Purpose |
|:--|:--|:--|
| Current | `age ≤ 1 cycle` | No action needed |
| Aging | `age ≤ 2 cycles` | Attention soon |
| Stale | `age ≤ 3 cycles` | Act on this |
| Very Stale | `age > 3 cycles` | Red flag |

For the 30-day fallback: Current ≤7d, Aging ≤30d, Stale ≤90d, Very Stale >90d.

## Visual Design

### Freshness bar

Interactive segmented bar above the evidence table. Proportions reflect the distribution across buckets. No counts or percentages displayed — the bar shape is the data. Tooltip on hover shows bucket name.

Clicking a segment creates a filter chip (`Freshness: Stale ✕`) per the [Filter Chip Pattern](filter-chip-pattern.md). Table filters to that bucket. Click ✕ to clear.

### Row background tint

Neutral shades, mode-adaptive. Communicates freshness regardless of table sort order.

| Bucket | Light mode | Dark mode |
|:--|:--|:--|
| Current | Soft gray-blue, barely visible | Muted teal-gray, subtle |
| Aging | Warm gray | Warm mid-gray |
| Stale | Slate | Cool light-gray |
| Very Stale | Charcoal tint | Near-white gray |

Constraints:
- Row text must remain readable in both modes
- Background applied at ~5-10% opacity, not solid fill
- No primary colors (no red/green/yellow/orange)
- Intensity communicates urgency: faint = fine, prominent = act

## Implementation Path

Parse policy content client-side. Build a `requirement_id → cycle_days` map from `adherence.assessment-plans[]`. Apply per-row when rendering the evidence table. Fall back to 30-day default when no plan matches.
