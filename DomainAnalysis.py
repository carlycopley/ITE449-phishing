# Add header comment

import checkdmarc

def AssignDmarcScore(domain, dmarcAnalysis):
	score = 100
	# Code from Claude used from here
	try: 
		result = checkdmarc.check_dmarc(domain)

		tags = result["tags"]

		policy = tags["p"]["value"]

		# if pct is not present in the record, it defaults to 100
		pct = tags.get("pct", {}).get("value", 100)

		if policy in ("quarantine", "reject"):
	# to here
			if policy in "reject":
				score = 0
				dmarcAnalysis.append("p is set to 'reject': DMARC Policy is STRONG")
			else:
				score = 25
				dmarcAnalysis.append("p is set to 'quarantine': DMARC Policy is OKAY")
		
			if pct < 100:
				score += (100 - pct)
				dmarcAnalysis.append("pct < 100: Set to 100 for stronger DMARC Policy")
		else:
			dmarcAnalysis.append("p is not set to 'reject' or 'quarantine': DMARC Policy is WEAK")

	# Claude used to determine what exceptions to use
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

def AssignSpfScore(domain, spfAnalysis):
	score = 100
	# Code from Claude used from here
	try:
		result = checkdmarc.check_spf(domain)
		dnsLookupCount = result["dns_lookups"]
	# to here
		
		if dnsLookupCount <= 10:
			spfAnalysis.append("DNS Lookup Count is within a safe range.")
			if dnsLookupCount >= 6:
				spfAnalysis.append("DNS Lookup Count is close to maximum (10).")
		
			score = dnsLookupCount * 10
		else:
			spfAnalysis.append("DNS Lookup Count is NOT within a safe range. Limit lookups to 10.")
		
		if score in range(0, 30):
			spfAnalysis.append("SPF Risk Score is LOW.")
		elif score in range(40, 60):
			spfAnalysis.append("SPF Risk Score is MEDIUM.")
		else:
			spfAnalysis.append("SPF Risk Score is HIGH.")

	except Exception as e:
		message = "Unexpected error determining SPF Risk Score: " + str(e)
		spfAnalysis.append(message)

	return score

def AssignBrandImpScore(domain, brandImpAnalysis):
	score = 0
	
	trustworthyTlds = [".com", ".org", ".de", ".br", ".ru", ".uk", ".net", ".jp",
		".it", ".fr", ".gov", ".edu", ".co", ".us", ".ai", ".io", ".shop",
		".online", ".inc", ".llc", ".info", ".xyz"]

	financialNames = [".finance", ".bank", ".loan", ".loans", ".credit", ".money",
		".cash", ".accountant", ".accountants", ".tax", ".fund", ".capital",
		".bond", ".insurance", ".investments", ".trading", "bank"]

	popularBrands = ["google", "amazon", "instagram", "facebook", "x", "pinterest",
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

# Hard-coded for now, but will use domain input by user.
# Add validation to make sure user is entering a valid domain name.
domain = "google.com"

# DMARC Record Risk Score
dmarcAnalysis = []
dmarcScore = AssignDmarcScore(domain, dmarcAnalysis)
print("The DMARC Record Risk Score is", dmarcScore)

for entry in dmarcAnalysis:
	print(entry)

print()

# SPF Record Risk Score
spfAnalysis = []
spfScore = AssignSpfScore(domain, spfAnalysis)
print("The SPF Record Risk Score is", spfScore)

for entry in spfAnalysis:
	print(entry)

print()

# Brand Impersonation Risk Score
brandImpAnalysis = []
brandImpScore = AssignBrandImpScore(domain, brandImpAnalysis)
print("The Brand Impersonation Risk Score is", brandImpScore)

for entry in brandImpAnalysis:
	print(entry)

# Overall Risk Score
overallRiskScore = (dmarcScore + spfScore + brandImpScore) / 3
print("The Overall Risk Score is", round(overallRiskScore))

print()
