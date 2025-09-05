Phone Investigator
Phone Investigator is a versatile, investigator-focused phone intelligence and OSINT gathering tool. It analyzes phone numbers for validation, fraud risk, social presence, breach exposure, carrier/location data, and more, using public data, APIs, and custom heuristics.

Features
Phone Number Parsing & Validation: Parses and validates phone numbers using international formats and the phonenumbers library.

Carrier, Location, and Prefix Mapping: Automatically identifies carrier, operator region, and supports custom CSV imports for Indian prefixes.

Spam/Fraud Detection: Checks public spam databases (WhoCallsMe, Tellows) and supports optional external spam APIs.

Social Presence Enumeration: Best-effort lookups via DuckDuckGo for social profiles (Facebook, Instagram, LinkedIn, Telegram) and Instagram topsearch.

Breach Exposure Analysis: Searches local breach files and optional HaveIBeenPwned (HIBP) integration for phone-number related leaks.

VoIP/Disposable/SMS Gateway Detection: Leverages API and heuristic checks to flag risky number types.

Risk Scoring: Aggregates findings into a quantitative fraud risk score with explanations.

Batch Processing: Efficiently runs analysis on multiple numbers with concurrent processing and export options.

Menu-Driven UI: Robust CLI interface for all operations, cache control, and export functions.

Persistent Caching: Uses SQLite for fast repeated lookups and API quota control.

Graph Export: Outputs nodes and edges (CSV) showing connections from breaches and social pivots for analysis.

Installation
bash
git clone <repo-url>
cd PhoneInvestigator
pip install -r requirements.txt
python PhoneInfo.py
Optional: Set environment variables in a .env file for API keys (Twilio, NumVerify, HIBP, spam APIs).

Usage
Run interactively via menu interface for single or batch analysis.

Output results in JSON, CSV, or TXT format.

Integrate custom CSV prefix maps and breach files for advanced localization and exposure checks.

Installation
bash
git clone <repo-url>
cd PhoneInvestigator
pip install -r requirements.txt
python PhoneInfo.py
Optional: Set environment variables in a .env file for API keys (Twilio, NumVerify, HIBP, spam APIs).

Usage
Run interactively via menu interface for single or batch analysis.

Output results in JSON, CSV, or TXT format.

Integrate custom CSV prefix maps and breach files for advanced localization and exposure checks.

Requirements
Python 3.x

pip install phonenumbers python-dotenv requests pyfiglet termcolor beautifulsoup4

License
Specify your license (MIT, GPL, proprietary, etc.).

Disclaimer
Intended for responsible investigation and cyber defense use only. Respect all data privacy and legal regulations in your jurisdiction.
