**🛡️ WebVAPT-Intel-Aggregator**

A specialized, high-signal CLI tool designed to automate vulnerability research, payload discovery, and reference aggregation for security professionals.

📋 Features

Live Intelligence Gathering: Fetches community writeups, verified HackerOne public disclosure reports, and security research center insights.

Payload Discovery: Automatically retrieves weaponized payloads and wordlists via community repositories.

OWASP WSTG Integration: Directly integrates with official OWASP Web Security Testing Guide categories and test cases.

Robust Error Handling: Implements rate-limit management and smart query sanitization.

Automated Execution: Performs direct live lookups without synthetic generation risks.

🚀 Installation

Ensure you have Python 3.8+ installed, then clone the repository and install dependencies:
```
git clone https://github.com/your-username/vapt-intel-engine.git
cd vapt-intel-engine
```

💻 Usage

Run the engine from your terminal:

```
python vapt_engine.py
```

Select an OWASP category from the interactive menu to fetch live test cases, descriptions, remediation guidelines, community writeups, and payload sources.

🛠️ Tech Stack & Requirements

Language: Python 3.x

Dependencies: ddgs (DuckDuckGo Search API), standard library (urllib, json, re)

⚠️ Disclaimer

[!WARNING]
This script is not AI; it fetches live public links and test cases for each vulnerability category. Results are automated and may occasionally contain inaccuracies. Use responsibly and only on authorized targets.

📄 License

Distributed under the MIT License. See LICENSE for more information.
