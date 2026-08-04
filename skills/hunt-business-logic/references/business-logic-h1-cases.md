# Business Logic — HackerOne Cases

## Top Bounties
| Amount | Company | Bug |
|--------|---------|-----|
| $10,000 | Coinbase | Double Payout via PayPal (race+logic) |
| $7,500 | Valve | Modify in-flight payment data |
| $5,000 | Reddit | Approve admin approval without permission |
| $5,000 | Stripe | Unlimited fee discounts |

## Business Logic Taxonomy (356 reports, $80,619 total)

### Payment & Billing
- Negative numbers, overflow, decimal manipulation
- Currency conversion edge cases
- Tax calculation bypass
- Fee manipulation

### Coupon & Discount Abuse
- Reuse same code on multiple accounts
- Stack multiple coupons
- Negative discount amounts
- Race condition on validation
- Expired coupons that still work

### Workflow Bypass
- Skip steps in multi-step process
- Reorder steps (final step first)
- State manipulation (pending→delivered)
- Approve without permission

### Race + Logic Combo
- Two concurrent requests → both succeed
- Cancel + pay simultaneously
- Refund + purchase at same time

## Detection Mindset
"If all you do is look for IDORs, you might overlook bugs in the permissioning system itself."

## Testing Checklist
1. Test pricing with negative numbers
2. Test quantity with -1 or 0
3. Test coupon reuse across accounts
4. Test race conditions on state changes
5. Test workflow step skipping
6. Test default permissions
7. Test admin approval bypass
8. Test payment callback manipulation
