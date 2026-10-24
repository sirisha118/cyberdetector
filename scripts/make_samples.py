"""Create sample .eml files in ./samples (phishing, spam, malware, legitimate)."""
import os
from email.message import EmailMessage

OUT = os.path.join(os.path.dirname(__file__), "..", "samples")
os.makedirs(OUT, exist_ok=True)


def save(name, msg):
    with open(os.path.join(OUT, name), "wb") as fh:
        fh.write(msg.as_bytes())


m = EmailMessage()
m["From"] = '"PayPal Security" <security@paypa1-support.com>'
m["To"] = "victim@example.com"
m["Reply-To"] = "helpdesk@mail-recovery.top"
m["Subject"] = "URGENT: Your account has been limited - verify your identity"
m["Message-ID"] = "<phish1@cybershield.sample>"
m["Authentication-Results"] = "mx.example.com; spf=fail; dkim=none; dmarc=fail"
m.set_content("Dear customer,\n\nWe noticed unusual activity on your PayPal account. Your account will be suspended "
              "within 24 hours. Verify your account and confirm your password immediately:\n"
              "http://paypal.com.secure-login.verify-account.xyz/signin\n\nPayPal Security Team")
m.add_alternative('<p>Dear customer, unusual activity detected. <a href="http://198.51.100.23/paypal/login">'
                  'https://www.paypal.com/myaccount</a></p>', subtype="html")
save("phishing.eml", m)

m = EmailMessage()
m["From"] = "Prize Center <winner@lucky-prizes.click>"
m["To"] = "you@example.com"
m["Subject"] = "CONGRATULATIONS!!! YOU HAVE WON $1,000,000"
m["Message-ID"] = "<spam1@cybershield.sample>"
m.set_content("You are our lucky winner! Claim your prize now - 100% free, no obligation!!! Click here: "
              "http://bit.ly/3xPrize . Make money fast, earn $5000 a week. Unsubscribe below.")
save("spam.eml", m)

m = EmailMessage()
m["From"] = "Accounts <billing@invoices-portal.net>"
m["To"] = "finance@example.com"
m["Subject"] = "Invoice attached - payment overdue"
m["Message-ID"] = "<mal1@cybershield.sample>"
m.set_content("Please see the attached invoice. Payment overdue, open the attachment immediately.")
eicar = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
m.add_attachment(eicar, maintype="application", subtype="octet-stream", filename="Invoice_2024.pdf.exe")
save("malware.eml", m)

m = EmailMessage()
m["From"] = "Priya Sharma <priya@company-example.org>"
m["To"] = "you@example.org"
m["Subject"] = "Notes from Tuesday's roadmap meeting"
m["Message-ID"] = "<ham1@cybershield.sample>"
m["Authentication-Results"] = "mx.example.org; spf=pass; dkim=pass; dmarc=pass"
m.set_content("Hi,\n\nAttaching the notes from our roadmap meeting. Can we sync on Thursday at 3pm to go over "
              "next steps? The shared doc is at https://docs.company-example.org/roadmap\n\nThanks,\nPriya")
save("legitimate.eml", m)
print("samples written to", os.path.abspath(OUT))
