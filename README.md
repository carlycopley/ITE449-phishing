# ITE449-phishing
## Spring 2026 Infrastructure Security Group Project
This tool analyzes domains to determine their overall risk score. The lower the risk score, the safer the domain is. Each domain entered
will receive an overall score, which is the result of averaging three other individual risk scores. The individual risk scores check the domain's
DMARC record, SPF record, and brand impersonation risk. This tool is helpful in providing suggestions to improve domain security.

## Usage Notes
- This tool will not run correctly if DNS lookup is blocked by your network connection.
- For this tool to run on your machine, you must first have Python, Flask, and the checkdmarc library installed.
 - To use this tool, navigate to correct folder in command prompt:
 	- enter: py DomainAnalysis.py
  	- navigate to http://127.0.0.1:5000
   	- use CTRL+C in command prompt to quit

## Research Paper
(We will include link to final research paper here once completed.)

## Figures
[Wireframe](https://raw.githubusercontent.com/carlycopley/ITE449-phishing/refs/heads/main/images/email_domain_analysis_wireframe.png)
