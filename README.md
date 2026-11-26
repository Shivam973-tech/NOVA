# NOVA
# Scam Checker

We made this project as a team to help people check whether a message, link or payment ID is a scam. You paste an SMS, a link or a payment ID (like name@bank) into the box and click Check Now. The page then shows a color result: green means safe, orange means suspicious and red means dangerous. It also shows a risk score out of 100.

## What it does
- Looks for scam words like "urgent", "KYC", "lottery" and "OTP"
- Checks links for warning signs like http, IP addresses, short links and strange endings like .xyz
- Matches domains and payment IDs with a small list of known scam entries
- Explains in simple points why the result was given

## What we used
- Frontend: HTML, CSS and JavaScript
- Backend: Python (only built-in modules)
- The frontend sends the text to the backend, and the backend sends back the result

## How to run
1. Run `python Backend/main.py`
2. Open `Frontend/index.html` in the browser
3. Paste a message and click Check Now


