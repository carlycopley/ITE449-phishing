# Domain Analysis Tool
# ____________________
# This program determines an overall domain risk score by finding individual
# risk scores for the domain's DMARC Record, SPF Record, and brand impersonation
# likelihood, and then averaging the individual scores to determine the overall
# risk score.
# ____________________
# Author: Lydia Sparks
# Some code snippets were assisted by Claude (claude.ai), Anthropic
# Areas assisted: Flask usage, DomainResults class, checkdmarc usage,
# and exception handling

from flask import Flask, request, render_template
from dataclasses import dataclass, field
from typing import Optional
import checkdmarc

app = Flask(__name__)

# Used for simple data handling in HTML script.
@dataclass
class DomainResults:
	domain: str
	overallScore: Optional[int] = None
	dmarcScore: Optional[int] = None
	spfScore: Optional[int] = None
	brandImpScore: Optional[int] = None
	dmarcMessages: list = field(default_factory=list)
	spfMessages: list = field(default_factory=list)
	brandImpMessages: list = field(default_factory=list)
	overallMessages: list = field(default_factory=list)

# AssignDmarcScore() determines a domain's DMARC Record risk score, where
# it checks if p is quarantine or reject and that pct is 100 (fully enforced).
def AssignDmarcScore(domain, dmarcAnalysis):
	score = 100

	try: 
		result = checkdmarc.check_dmarc(domain)
		
		# if network connection blocks DNS query or other lookup failure
		if not result or "tags" not in result:
			dmarcAnalysis.append("DNS lookup failed.")
			return score

		# extracting needed info from DMARC record
		tags = result["tags"]

		policy = tags["p"]["value"]

		# if pct is not present in the record, it defaults to 100
		pct = tags.get("pct", {}).get("value", 100)

		if policy in ("quarantine", "reject"):
			if policy in "reject":
				score = 0
				dmarcAnalysis.append("p is set to 'reject': DMARC Policy is STRONG.")
			else:
				score = 25
				dmarcAnalysis.append("p is set to 'quarantine': DMARC Policy is OKAY.")
		
			if pct < 100:
				score += (100 - pct)
				dmarcAnalysis.append("pct < 100: Set to 100 for stronger DMARC Policy.")
		else:
			dmarcAnalysis.append("p is not set to 'reject' or 'quarantine': DMARC Policy is WEAK.")

	except checkdmarc.dmarc.DMARCRecordNotFound:
		dmarcAnalysis.append("No DMARC Record was found.")
	except KeyError:
		dmarcAnalysis.append("DMARC Record is present, but the 'p' tag is missing, meaning the policy is not enforced.")
	except checkdmarc.dmarc.DMARCError as e:
		message = "DMARC Error occurred when determining DMARC Risk Score: " + str(e)
		dmarcAnalysis.append(message)
	except Exception as e:
		message = "Unexpected error determining DMARC Risk Score: " + str(e)
		dmarcAnalysis.append(message)

	return score

# AssignSpfScore() determines a domain's SPF Record risk score, where it checks
# the number of DNS lookups. To stay within a safe range, the lookup count cannot
# exceed 10.
def AssignSpfScore(domain, spfAnalysis):
	score = 100

	try:
		# gets number of DNS lookups
		result = checkdmarc.check_spf(domain)
		dnsLookupCount = result["dns_lookups"]
		
		if dnsLookupCount <= 10:
			message = "DNS Lookup Count is within a safe range: " + str(dnsLookupCount) + " lookups."
			spfAnalysis.append(message)
			if dnsLookupCount >= 6:
				spfAnalysis.append("DNS Lookup Count is close to the maximum of 10 lookups.")
		
			score = dnsLookupCount * 10
		else:
			spfAnalysis.append("DNS Lookup Count is NOT within a safe range. Limit lookups to 10.")
		
		if score in range(0, 40):
			spfAnalysis.append("SPF Risk Score is LOW.")
		elif score in range(40, 70):
			spfAnalysis.append("SPF Risk Score is MEDIUM.")
		else:
			spfAnalysis.append("SPF Risk Score is HIGH.")

	except Exception as e:
		message = "Unexpected error determining SPF Risk Score: " + str(e)
		spfAnalysis.append(message)

	return score

# AssignBrandImpScore() determines a domain's brand impersonation risk score,
# where it checks if part of a domain name belongs to any entry in three lists:
# trustworthyTlds, financialNames, and popularBrands. If it belongs to one or
# more of the lists, the risk score increases.
def AssignBrandImpScore(domain, brandImpAnalysis):
	score = 0
	
	trustworthyTlds = [".com", ".org", ".de", ".br", ".ru", ".uk", ".net", ".jp",
		".it", ".fr", ".gov", ".edu", ".co", ".us", ".ai", ".io", ".shop",
		".online", ".inc", ".llc", ".info", ".xyz"]

	financialNames = [".finance", ".bank", ".loan", ".loans", ".credit", ".money",
		".cash", ".accountant", ".accountants", ".tax", ".fund", ".capital",
		".bond", ".insurance", ".investments", ".trading", "bank"]

	popularBrands = ["google", "amazon", "instagram", "facebook", "pinterest",
		"linkedin", "youtube", "tiktok", "walmart", "target", "disney",
		"microsoft", "apple", "netflix", "hulu", "hbo"]

	lowerCaseDomain = domain.lower()

	if any(sub in lowerCaseDomain for sub in trustworthyTlds):
		score += 50
		brandImpAnalysis.append("Domain name contains a trustworthy TLD.")
	
	if any(sub in lowerCaseDomain for sub in financialNames):
		score += 30
		brandImpAnalysis.append("Domain name contains financial TLD or wording.")

	if any(sub in lowerCaseDomain for sub in popularBrands):
		score += 20
		brandImpAnalysis.append("Domain name contains a popular brand or service.")

	return score

# AnalyzeDomain() calls each individual score function and averages the scores
# to determine the overall risk score. All the data is assigned to the DomainResults
# fields.
def AnalyzeDomain(domain):
	results = DomainResults(domain=domain)

	overallAnalysis = []

	# DMARC Record Risk Score
	dmarcAnalysis = []
	dmarcScore = AssignDmarcScore(domain, dmarcAnalysis)

	# SPF Record Risk Score
	spfAnalysis = []
	spfScore = AssignSpfScore(domain, spfAnalysis)

	# Brand Impersonation Risk Score
	brandImpAnalysis = []
	brandImpScore = AssignBrandImpScore(domain, brandImpAnalysis)

	# Overall Risk Score
	overallRiskScore = round((dmarcScore + spfScore + brandImpScore) / 3)

	if overallRiskScore >= 80:
		overallAnalysis.append("ALERT: If this domain is valid, we suggest reporting it to the Internet Crime Complaint Center (IC3) for further investigation.")

	results.overallScore = overallRiskScore
	results.dmarcScore = dmarcScore
	results.spfScore = spfScore
	results.brandImpScore = brandImpScore
	results.dmarcMessages = dmarcAnalysis
	results.spfMessages = spfAnalysis
	results.brandImpMessages = brandImpAnalysis
	results.overallMessages = overallAnalysis

	return results

# Sends the results to the HTML script if a domain is submitted.
@app.route("/", methods=["GET", "POST"])
def index():
	results = None

	if request.method == "POST":
		domain = request.form.get("domainSubmitted", "").strip()
		if domain:
			results = AnalyzeDomain(domain)
	
	return render_template("index.html", results=results)

if __name__ == "__main__":
	app.run(debug=True)
