# Payment Flaws — Complete Iranian Payment Testing

Source: Free Stay Paradise (@_free_stay)

## PAYMENT FLOW
1. ثبت سفارش → 2. انتخاب شیوه پرداخت → 3. ارسال به PSP→Token
4. هدایت به درگاه → 5. پرداخت → RefNum → 6. اطلاعات به فروشنده
7. استعلام از PSP → 8. تأیید/رد

> اکثر PSPها فقط RefNum چک میکنن (به جز سداد و به‌پرداخت)

## 1. PAYMENT METHOD ENUMERATION
JS Files | Fuzzing | Wayback | مبالغ بالا | بخش عمده
مشهور: `cheque-companyname` از بخش عمده → خرید رایگان!

## 2. PAYMENT DoS
انصراف بدون validation → همه فاکتورها لغو (ResNum Auto-Increment)

## 3. IDOR: PAY LESS
فاکتور مبلغ بالا → ResNum ذخیره → فاکتور کم پرداخت → جایگزین ResNum

## 4. DOUBLE SPENDING
Logic: انصراف با RefNum=NULL → RefNum پاک → دوباره ارسال
Race: دو فاکتور → یکی انصراف یکی پرداخت → همزمان → هر دو تأیید

## 5. PAYMENT + REFUND
دو فاکتور مبلغ مختلف → ResNum مبلغ بیشتر → اولی تأیید دومی برگشت

## 6. ATO VIA CALLBACK
کوکی منقضی → سامانه کوکی وابسته به ResNum برمیگردونه

## 7. WALLET RACE
انصراف → درخواست برگشت همزمان تکرار | Currency Confuse | IDOR+CSRF

## 8. DISCOUNT CODE DOUBLE SPEND
دو سفارش/حساب → کد تخفیف همزمان روی هر دو

## 9. SMS-WALLET PAYMENT FLOW (PodBox Pattern)
```
1. POST /contents/{videoId}/invoices → Invoice + pay.pod.ir link
2. POST /contents/{videoId}/invoices/{id}/voucher → Discount code
3. POST /contents/{videoId}/invoices/{id}/sms → SMS confirmation
4. POST /contents/{videoId}/invoices/{id}/sms/confirm → Wallet deduction
```

## RANKING
IDOR مبلغ کمتر: 🟡 متوسط | Double Spending: 🔴 خیلی بالا
Wallet IDOR+CSRF: 🟢 بالا | کد تخفیف: 🟢 بالا
