[Español](../transparencia.md) | **English**

# Transparency

DepSentinel is free. Donations are optional and **never unlock features**.

## Rules

1. Every feature is free for everyone. Donating or sponsoring gives no access to rules, formats or integrations that
   others do not have.
2. Every month we publish how much came in and what it was spent on (this page and the website's transparency page).
3. Companies can sponsor and be listed as such, but they get no priority on issues, no custom changes and no vote on
   the detection rules.
4. If there is money left, it goes back into the project: first maintenance, then independent security audits.
   Spending decisions are discussed in the open (issues or discussions in the repository).

## How to update the accounts each month

Edit **one** file, `web/landing/transparency-data.json`. Both the Spanish and the English pages read it:

```json
{
  "currency": "EUR",
  "updated": "2026-12-01",
  "months": [
    {
      "month": "2026-11",
      "donations": 40,
      "sponsorships": 100,
      "costs": { "domain": 12, "audits": 0, "other": 9.5 },
      "note": "First company sponsorship"
    }
  ]
}
```

* `month`: `YYYY-MM`. `donations` and `sponsorships`: amounts received. `costs`: any set of items (they are summed).
  `note`: optional free text.
* The page computes the totals, each month's balance and the running balance; there is nothing to add up by hand.
* The pages load the file with `fetch`, so to preview them locally serve the folder
  (`cd web/landing && python3 -m http.server`) instead of opening the file directly.
* Also add the month to the table below to keep the history in the repository.

## History

| Month | Donations | Sponsorships | Costs | Notes |
|---|---|---|---|---|
| _No transactions yet._ | | | | |

## Verifiable accounts

Use a platform with a public ledger (Open Collective publishes every transaction) or link the receipts, so anyone
can check the figures without trusting this page.
