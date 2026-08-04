# Business Logic — All H1 Reports & Cases

## Source: 356 reports, $80,619 total (four-missing-categories.md)

## Top Bounties (from H1 reports)
| Amount | Company | Bug Type |
|--------|---------|----------|
| $10,000 | Coinbase | Double Payout via PayPal (race+logic) |
| $7,500 | Valve | Modify in-flight payment data |
| $5,000 | Reddit | Approve admin approval without permission |
| $5,000 | Stripe | Unlimited fee discounts |
| $1,500 | — | Project Secrets Management (business logic) |
| $500 | — | Race condition on financial operations |

## 1. PAYMENT FLOW BYPASS
- Skip payment step → get product for free
- Modify in-flight payment data mid-transaction
- Negative amount → credit instead of debit
- Zero amount invoice → free access
- Decimal manipulation: $9.99 → $999.00

## 2. DOUBLE PAYOUT / DOUBLE SPEND
- Race condition: two concurrent payment requests
- Both pass validation before balance check
- Both result in payout → double profit
- Coinbase: $10K PayPal double payout
- RefNum=NULL trick (Persian banking pattern)

## 3. WORKFLOW BYPASS
- Skip approval steps in multi-step process
- Reorder steps (final step first)
- Bypass sequential validation
- Submit final state without intermediate states

## 4. STATE MANIPULATION
- Change order status: pending → delivered
- Change invoice status: unpaid → paid
- Change refund status: requested → approved
- Modify timestamps in requests

## 5. COUPON/DISCOUNT ABUSE
- Reuse same coupon code across multiple accounts
- Stack multiple coupons on single order
- Apply negative discount → add funds
- Bypass coupon expiry (expired still works)
- Bypass usage limit (unlimited uses)
- Currency-specific coupon applies to wrong currency
- Stripe: Unlimited fee discounts ($5K)

## 6. WALLET/PRICING MANIPULATION
- Currency Confuse: deposit IRR → USD wallet credited
- Exchange rate manipulation during transaction
- Quantity overflow: max_int → huge balance
- Fractional quantities with rounding bugs

## 7. PRICING/BILLING LOGIC
- Test with negative numbers
- Test overflow boundaries (max int, max float)
- Test decimal precision (banker's rounding)
- Test quantity with 0, -1, very large numbers
- Tax calculation bypass
- Fee structure manipulation

## 8. ROLE/ADMIN APPROVAL BYPASS (-Reddit $5K)
- Approve admin approval without having permission
- Skip approval workflow → become admin
- Default permissions on invite (Admin until accepted)
- Window: invite sent → accepted = privileges escalate

## 9. PAYMENT CALLBACK MANIPULATION
- Tamper with callback parameters
- ResNum swap between invoices
- Replay old callbacks
- Modify callback state (Pending→Confirmed)

## 10. DEFAULT PERMISSIONS BUG
- Invited users get admin permission before acceptance
- New users inherit elevated default roles
- Missing permission check on first action
- "If all you do is look for IDORs, you might overlook bugs in the permissioning system itself."

## Testing Checklist (run ALL before reporting "not vulnerable")
1. [ ] Negative amounts / quantities
2. [ ] Zero value operations
3. [ ] Maximum boundary values (int, float)
4. [ ] Decimal manipulation (rounding, precision)
5. [ ] Coupon reuse across accounts
6. [ ] Coupon stacking
7. [ ] Expired coupon usage
8. [ ] State manipulation (pending→approved)
9. [ ] Workflow step skipping
10. [ ] Race condition (concurrent requests)
11. [ ] Default permissions check
12. [ ] Admin approval bypass
13. [ ] Payment callback tampering
14. [ ] Currency confusion
15. [ ] Double spend / double payout
16. [ ] Quantity = -1 or 0

## H1 Reports Referenced
- missing-categories-complete.md (Business Logic section)
- four-missing-categories.md (356 reports, $80,619)
- a13h1-writeups.md (writeup extract)
- payment-flaws-iranian.md (Iranian banking patterns)
- h1-idor-domxss-sqli-extract.md (cross-reference)
- monke-methodology-guide.md (detection mindset)

## Key Insight
Business Logic bugs are often MISSED because testers focus only on IDOR/Auth bypass.
Every state-changing endpoint needs Logic testing in addition to Access Control testing.
