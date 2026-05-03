# Investor Update Feature — Design Spec

**Date:** 2026-05-03
**Status:** Approved by Eddie, ready for implementation plan
**Project:** cfo-dashboard-portal

## 1. Overview

A new tab in the CFO Dashboard that lets each logged-in client generate a monthly investor update deck driven by their QBO data. Output is an HTML preview rendered as 6 slides (16:9 landscape) plus a Print/Save PDF button. Two of the six slides accept manual narrative input (highlights, asks); the other four are fully auto-generated from QBO. Manual fields are saved per period so clients build a historical record of their updates.

**Goal:** give CBA clients a self-serve, repeatable monthly investor-update workflow that takes minutes instead of hours.

**Non-goal (v1):** pitch decks for fundraising, PPTX export, multi-investor mailing lists, comment threads, or live charts that update post-export.

## 2. User flow

1. Client logs into the dashboard (existing auth).
2. Clicks the new `📊 Investor Update` tab.
3. Sees a period selector defaulted to the most recent closed month (e.g., April 2026 if today is May 3, 2026).
4. Sees two text areas pre-populated with any saved content for that period (Highlights, Asks).
5. Sees the live deck preview (6 slides) below, populated with QBO data for the selected period.
6. Edits the text areas. Content auto-saves on blur.
7. Clicks **Print / Save PDF** to export.
8. Optionally switches to a different month to view or edit a prior update.

## 3. Slide spec

### Slide 1 — Cover (auto)
- Client company name (from existing `clientCompanyName` resolver)
- Period label, e.g., "April 2026 Update"
- Generated date
- "Prepared by Clear Books Advisory" small footer

### Slide 2 — TL;DR / Highlights (manual)
- Heading: "Highlights"
- Body: rendered Markdown-ish bullets from `highlights_text` field
- If empty: render a placeholder hint visible only on screen, hidden on print

### Slide 3 — Revenue & growth (auto)
- Hero stat: total revenue for the selected month
- Two badges: MoM % change and YoY % change
- Channel breakdown bar chart: revenue by income account for the month (Stripe, Amazon, PayPal, etc.) using existing P&L row data
- Requires 3 P&L API calls: current month, prior month, same month prior year

### Slide 4 — P&L summary (auto)
- Two-column comparison: current month vs. prior month
- Rows: Revenue, COGS, Gross Profit, Gross Margin %, Operating Expenses, Net Income
- Variance column showing $ and % change
- Requires 2 P&L API calls (already fetched in Slide 3)

### Slide 5 — Cash & runway (auto)
- Hero stat: cash balance from BS as of period end
- Burn rate: monthly burn = `-net_income` for the month (Option A methodology, locked during scoping)
- Runway: `cash_balance / monthly_burn` rounded to nearest 0.1 month; show "∞" if burn ≤ 0 (profitable)
- Small line chart: cash trend across the last 6 months (requires 6 BS API calls; cache aggressively)

### Slide 6 — Asks & next month (manual)
- Heading: "What we need from you / What's next"
- Body: rendered from `asks_text` field
- If empty: same placeholder treatment as Slide 2

## 4. Backend

### Database — new table

```sql
CREATE TABLE IF NOT EXISTS investor_updates (
  id           SERIAL PRIMARY KEY,
  user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  period_year  INTEGER NOT NULL,
  period_month INTEGER NOT NULL CHECK (period_month BETWEEN 1 AND 12),
  highlights_text TEXT DEFAULT '',
  asks_text       TEXT DEFAULT '',
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (user_id, period_year, period_month)
);

CREATE INDEX IF NOT EXISTS idx_investor_updates_user_period
  ON investor_updates (user_id, period_year DESC, period_month DESC);
```

Migration runs on startup via `initDB()` in `db.js` (same pattern as existing tables).

### API endpoints — new

```
GET  /api/investor-update?year=YYYY&month=M
     → 200 { highlights_text, asks_text, updated_at }
     → 200 { highlights_text: "", asks_text: "", updated_at: null } if no record yet
     Auth: requires session, scopes by req.session.userId

POST /api/investor-update
     Body: { year, month, highlights_text, asks_text }
     → 200 { ok: true, updated_at }
     Upserts on (user_id, year, month). Validates month range.
     Auth: requires session.
```

### QBO data reuse

No new QBO endpoints. The slide renderer calls existing `/api/pnl` and `/api/balance-sheet` with the appropriate date ranges. Three `/api/pnl` calls fire in parallel (current, prior, YoY); BS calls fire in parallel for the cash trend.

## 5. Frontend

### Tab integration

Add a new tab button in the existing `<nav class="tab-nav">`:

```html
<button class="tab-btn" onclick="switchTab('investor',this);loadInvestor()">📊 Investor Update</button>
```

Add a new panel `<div class="tab-panel" id="tab-investor">` containing:
- Period selector (`<select>` with last 12 closed months)
- Two `<textarea>` blocks for highlights and asks
- A `<div id="deckPages">` for the rendered slides

### CSS

New class `.deck-slide`:
- Width: 1056px (matches existing landscape pages)
- Height: 594px (16:9 ratio at 1056px width)
- Padding: 48px 64px
- Cover slide gets a hero treatment (large Cormorant Garamond title)
- Stat slides use 36pt+ for hero numbers, 12pt for supporting copy

New `@page` rule:
```css
@page deck-page { size: letter landscape; margin: 0.4in; }
@media print { .deck-slide { page: deck-page; } }
```

### State management

- `currentInvestorPeriod` — `{year, month}` reflecting dropdown selection
- Manual fields auto-save on `blur` (when client clicks away from a textarea) and on period change
- On period change: save current draft, fetch new period's record, refetch QBO data for new period, re-render slides
- On QBO 401: existing connect-screen flow handles it, no new logic

## 6. Edge cases

| Case | Behavior |
|---|---|
| Brand-new client, no prior month exists | Slide 3 suppresses MoM badge; Slide 4 hides "prior" column with a "No comparison data" note; Slide 5 cash trend shows whatever months exist |
| Mid-month export (e.g., May 3 export of May data) | Period selector excludes the in-progress month from the default; client can manually pick it but header label reads "Month-to-date through May 3, 2026" |
| Zero revenue or zero prior revenue | Show "—" instead of `Infinity%` or `NaN%` |
| Negative gross margin | Display in red, no special handling otherwise |
| Burn ≤ 0 (profitable) | Slide 5 runway shows "∞" with subtitle "Profitable" |
| Manual fields empty | Render placeholder hint on screen, hide on print so the slide isn't visually broken |
| QBO token expired | Existing 401 handler triggers connect-screen flow |
| Two browser tabs editing same period | Last-save-wins; acceptable for v1 (single user per account in normal use) |

## 7. Out of scope for v1

- PPTX export
- Pitch-deck variant (cover, problem, solution, market, traction, team, ask) — defer until at least one client requests it
- Quarterly cadence
- Custom slide reordering or hidden slides
- Email-from-app workflow
- Investor portal sharing (read-only links)
- Comments / collaboration on the update
- Cohort, customer, or LTV analytics (out of QBO data reach without integrations)

## 8. Future work parking lot

- Add quarterly mode behind a toggle once monthly proves valuable
- Add YoY % to Slide 4 once monthly data has 12+ months of history
- Add a "Send to investor list" feature (email integration, ID list per client)
- Replace burn methodology with cash-flow-statement based calc (Option C from scoping) once QBO CF reliability is verified
- Optional pitch-deck template if a client requests fundraising support

## 9. Open questions to confirm before implementation

None at design close. Burn methodology, output format, slide structure, and tab placement all locked during the brainstorming pass.
