"""Generate a synthetic labelled training set (ham / spam / phishing).

This is DEMO data so the project works out of the box. For production accuracy,
retrain on a real corpus (e.g. SpamAssassin, Enron, Nazario phishing corpus):
    flask train-model --csv /path/to/your.csv      (columns: text,label)
"""
import csv
import os
import random

random.seed(42)
OUT = os.path.join(os.path.dirname(__file__), "..", "app", "ml", "data", "sample_emails.csv")

names = ["Alex", "Priya", "Jordan", "Sam", "Maria", "Chen", "Ravi", "Taylor", "Dana", "Omar"]
projects = ["Q3 roadmap", "website redesign", "onboarding docs", "budget review", "API migration",
            "customer survey", "sprint planning", "release 2.4", "vendor contract", "data pipeline"]
days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
brands = ["PayPal", "Microsoft", "Amazon", "Apple", "Netflix", "Google", "DHL", "your bank", "HDFC Bank", "Facebook"]

ham_t = [
    "Hi {n}, attaching the notes from our {p} meeting. Can we sync on {d} at 3pm to go over next steps?",
    "Reminder: the {p} review is scheduled for {d}. Please add your comments to the shared document before then.",
    "Thanks for the update on {p}. I looked through the draft and left a few suggestions inline. Let me know what you think.",
    "Team, the weekly newsletter is out. This week: {p} progress, new hires, and the office schedule for {d}.",
    "Hey {n}, are we still on for lunch {d}? Let me know if you want to try the new place downtown.",
    "Your order has shipped and will arrive {d}. Track it from your account page. Thank you for shopping with us.",
    "Please find the minutes of the {p} call. Action items are listed at the bottom, owners marked in bold.",
    "Hi {n}, the invoice for last month's hosting is attached for your records. No action needed, payment is automatic.",
    "Can you review my pull request for the {p}? Tests pass locally and I updated the readme.",
    "Happy birthday {n}! The team got you a card, come by the kitchen at 4pm on {d} for cake.",
]
spam_t = [
    "CONGRATULATIONS! You have won a $1,000,000 lottery prize. Claim your prize now, 100% free, no obligation!!!",
    "Make money fast working from home! Earn $5000 a week with this risk-free exclusive deal. Click here today.",
    "Cheap pills online, no prescription needed. Weight loss miracle, limited offer. Unsubscribe at the bottom.",
    "Crypto giveaway! Double your bitcoin instantly. Click here to join the winners list, hurry!!!",
    "You are our lucky winner {n}! Free vacation to the Bahamas, claim your prize before midnight. Click here.",
    "Online casino bonus: 200 free spins and a $500 welcome deal. Play now, no deposit required!!!",
    "Hot singles in your area want to meet you. Click here for free access, no credit card, 100% free.",
    "Increase your followers overnight! Buy 10,000 likes cheap. Special promotion, order now and save 90 percent.",
    "Exclusive deal just for you: luxury watches at 90 percent off. Limited stock, click here to order.",
    "Refinance your mortgage today with the lowest rates ever. Apply now, no obligation, instant approval.",
]
phish_t = [
    "Security alert: unusual activity detected on your {b} account. Verify your account immediately or it will be suspended. Log in here to confirm your identity.",
    "Dear customer, your {b} password expires in 24 hours. Click the link below to update your password now to avoid account suspension.",
    "Action required: we could not process your payment. Update your payment details and card number within 24 hours to keep your {b} subscription.",
    "Your {b} account has been limited due to suspicious sign in. Confirm your identity and enter your password to restore access immediately.",
    "Final notice: unauthorized login attempt on your account. Sign in to verify your information or your account will be deactivated.",
    "Hello, we noticed a problem with your recent invoice. Download the attached document and sign in with your {b} credentials to view it.",
    "Please wire transfer the outstanding amount today to the new bank details below. Keep this confidential and reply once done. Are you available?",
    "Your package could not be delivered. Confirm your address and pay a small customs fee here to reschedule delivery from {b}.",
    "IRS notice: you are owed a tax refund. Verify your social security number and bank account to claim it before the deadline.",
    "I need a favor, are you available? Purchase gift cards for a client and send me the codes. I will reimburse you, keep this confidential.",
]


def make(t, label, n):
    rows = []
    for _ in range(n):
        s = random.choice(t).format(n=random.choice(names), p=random.choice(projects),
                                    d=random.choice(days), b=random.choice(brands))
        if label != "ham" and random.random() < 0.3:
            s = random.choice(["URGENT: ", "Re: ", "Fwd: ", "Notice: "]) + s
        rows.append((s, label))
    return rows


rows = make(ham_t, "ham", 200) + make(spam_t, "spam", 120) + make(phish_t, "phishing", 140)
random.shuffle(rows)
os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["text", "label"])
    w.writerows(rows)
print(f"wrote {len(rows)} rows -> {os.path.abspath(OUT)}")
