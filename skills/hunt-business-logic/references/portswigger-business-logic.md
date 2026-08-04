# PortSwigger Reference — Business Logic (11 Labs)

## Source
https://portswigger.net/web-security/business-logic

## Lab Categories (11 total)
- Pricing manipulation
- Coupon abuse
- Payment logic bypass
- Race conditions in business logic
- State manipulation
- Workflow bypass
- Access control in business logic
- Coupon reuse
- Payment amount manipulation
- Shopping cart logic
- Purchase quantity manipulation

## Key Topics (from H1 reports)
- Double payout via race condition (Coinbase $10K)
- Modify in-flight payment data (Valve $7.5K)
- Approve admin approval without permission (Reddit $5K)
- Unlimited fee discounts (Stripe $5K)

## Detection Mindset
"If all you do is look for IDORs, you might overlook bugs in the permissioning system itself."

## Testing Checklist
1. Negative quantities / amounts
2. Zero-value operations
3. Decimal manipulation
4. Coupon reuse across accounts
5. Coupon stacking
6. Expired coupon usage
7. State manipulation (pending→approved)
8. Workflow step skipping
9. Race conditions
10. Default permissions check
11. Admin approval bypass