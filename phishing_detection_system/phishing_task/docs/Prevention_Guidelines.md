# Phishing Prevention & Awareness Guidelines

## For End Users: How to Spot a Phishing Email

### 1. Check the Sender's Address
- **Do not trust the display name.** "PayPal Security" could be `security@paypal-fake.com`.
- Hover over the sender name to see the actual email address.
- Look for misspellings: `rnicrosoft.com` instead of `microsoft.com`.

### 2. Inspect Links Before Clicking
- **Hover over any link** to see the real URL in the bottom-left corner of your browser.
- If the displayed text (`www.paypal.com`) doesn't match the actual link (`http://192.168.1.1`), it's a scam.
- Be wary of URL shorteners (bit.ly, tinyurl) — they hide the destination.

### 3. Watch for Urgency & Threats
- Phrases like **"Act Now"**, **"Account Suspended"**, **"Immediate Action Required"**, and **"Unauthorized Login"** are red flags.
- Legitimate companies do not threaten immediate account closure via email.

### 4. Be Careful with Attachments
- Never open attachments from unknown senders.
- Dangerous file types: `.exe`, `.scr`, `.js`, `.vbs`, `.bat`, `.cmd`, `.ps1`.

### 5. Verify Before You Act
- If you receive an email about your bank, **call your bank** using the number on the back of your card.
- Do not use phone numbers or links provided in the suspicious email.

---

## For IT Administrators

### Technical Controls
1. **SPF (Sender Policy Framework):** Publish SPF records to prevent sender spoofing.
2. **DKIM (DomainKeys Identified Mail):** Sign outgoing emails with cryptographic signatures.
3. **DMARC:** Set policy to `p=reject` to block unauthenticated emails.
4. **Email Gateway:** Deploy solutions like Proofpoint, Mimecast, or open-source alternatives.
5. **Sandboxing:** Detonate attachments in a sandbox before delivery.
6. **URL Rewriting:** Rewrite links to scan them at click time.

### User Training
- Simulate phishing attacks quarterly.
- Track click rates and provide remedial training.
- Reward users who report phishing emails.

---

## Emergency Response: If You Clicked a Link
1. **Disconnect** from the network immediately.
2. **Change passwords** for the affected account (from a different device).
3. **Enable 2FA** if not already enabled.
4. **Report** to your IT/Security team.
5. **Run antivirus** and malware scans.
6. **Monitor** accounts for unusual activity.
