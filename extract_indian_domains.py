"""
Extract Indian domains from domain.csv and update indian_domains.py whitelist
"""
import pandas as pd
import re

print("=" * 80)
print("EXTRACTING INDIAN DOMAINS FROM domain.csv")
print("=" * 80)

# Load domain.csv
print("\n[1/4] Loading domain.csv...")
df = pd.read_csv('domain.csv', header=None, names=['index', 'domain'])
print(f"✓ Loaded {len(df)} domains")

# Indian domain patterns
indian_patterns = [
    r'\.in$',           # .in TLD
    r'\.co\.in$',       # .co.in
    r'\.org\.in$',      # .org.in
    r'\.net\.in$',      # .net.in
    r'\.gov\.in$',      # .gov.in
    r'\.ac\.in$',       # .ac.in (academic)
    r'\.edu\.in$',      # .edu.in (education)
]

# Known Indian brand keywords (for .com domains)
indian_keywords = [
    'india', 'indian', 'bharat', 'desi', 'mumbai', 'delhi', 'bangalore', 
    'bengaluru', 'chennai', 'kolkata', 'hyderabad', 'pune', 'ahmedabad',
    'flipkart', 'meesho', 'myntra', 'ajio', 'snapdeal', 'paytm', 'phonepe',
    'zomato', 'swiggy', 'ola', 'oyo', 'makemytrip', 'goibibo', 'yatra',
    'byjus', 'unacademy', 'vedantu', 'shaadi', 'naukri', 'indiamart',
    'redbus', 'irctc', 'jio', 'airtel', 'vodafone', 'tata', 'reliance',
    'icici', 'hdfc', 'sbi', 'axis', 'kotak', 'bajaj', 'mahindra'
]

print("\n[2/4] Filtering Indian domains...")

indian_domains = set()

# Find domains with .in TLD and variations
for pattern in indian_patterns:
    matches = df[df['domain'].str.contains(pattern, case=False, na=False, regex=True)]
    for domain in matches['domain']:
        indian_domains.add(domain.strip().lower())

# Find domains with Indian keywords
for keyword in indian_keywords:
    matches = df[df['domain'].str.contains(keyword, case=False, na=False, regex=False)]
    for domain in matches['domain']:
        indian_domains.add(domain.strip().lower())

print(f"✓ Found {len(indian_domains)} potential Indian domains")

# Filter out suspicious/generic domains
print("\n[3/4] Filtering out suspicious domains...")

def is_valid_indian_domain(domain):
    """Filter out suspicious patterns"""
    domain_lower = domain.lower()
    
    # Exclude if domain has suspicious patterns
    suspicious = [
        'test', 'demo', 'sample', 'example', 'localhost',
        'temp', 'spam', 'fake', 'phishing', 'malware',
        'xxx', 'porn', 'adult', 'casino', 'bet',
        '.su', '.tk', '.ml', '.ga', '.cf'  # Suspicious TLDs
    ]
    
    for sus in suspicious:
        if sus in domain_lower:
            return False
    
    # Exclude very short domains (likely typos)
    if len(domain) < 5:
        return False
    
    # Exclude domains with excessive numbers
    if sum(c.isdigit() for c in domain) > len(domain) * 0.5:
        return False
    
    # Exclude IP-like patterns
    if re.match(r'^\d+\.\d+\.\d+', domain):
        return False
    
    return True

filtered_domains = {d for d in indian_domains if is_valid_indian_domain(d)}
print(f"✓ Filtered to {len(filtered_domains)} valid domains")

# Separate by TLD
in_domains = {d for d in filtered_domains if d.endswith('.in') or '.in.' in d}
com_domains = {d for d in filtered_domains if d.endswith('.com')}
other_domains = filtered_domains - in_domains - com_domains

print(f"\n  • .in domains: {len(in_domains)}")
print(f"  • .com domains: {len(com_domains)}")
print(f"  • Other TLDs: {len(other_domains)}")

# Sort and display top domains
print("\n[4/4] Top Indian domains found:")
print("\n.IN Domains (sample):")
for domain in sorted(list(in_domains))[:20]:
    print(f"  • {domain}")

print("\n.COM Indian Brands (sample):")
for domain in sorted(list(com_domains))[:20]:
    print(f"  • {domain}")

# Create updated indian_domains.py
print("\n" + "=" * 80)
print("UPDATING indian_domains.py")
print("=" * 80)

# Read current indian_domains.py
with open('indian_domains.py', 'r', encoding='utf-8') as f:
    current_content = f.read()

# Extract existing domains
import ast
try:
    # Find the set definition
    start = current_content.find('INDIAN_TRUSTED_DOMAINS = {')
    end = current_content.find('}', start) + 1
    existing_set_str = current_content[start:end]
    
    # Parse existing domains
    existing_domains = set()
    for line in current_content.split('\n'):
        if "'" in line and '.com' in line or '.in' in line:
            # Extract domain from line like: 'meesho.com', 'meesho.in',
            matches = re.findall(r"'([^']+)'", line)
            existing_domains.update(matches)
    
    print(f"✓ Found {len(existing_domains)} existing domains")
except Exception as e:
    print(f"⚠ Could not parse existing domains: {e}")
    existing_domains = set()

# Combine with new domains
all_domains = existing_domains | filtered_domains

# Categorize domains
categories = {
    'E-commerce': [],
    'Fintech & Banking': [],
    'Food & Delivery': [],
    'Travel & Transport': [],
    'Education': [],
    'News & Media': [],
    'Technology & IT': [],
    'Government & Public': [],
    'Other .in domains': [],
    'Other Indian brands': []
}

# Categorization keywords
category_keywords = {
    'E-commerce': ['shop', 'cart', 'buy', 'store', 'mart', 'bazaar', 'market', 'flipkart', 'amazon', 'meesho', 'myntra', 'ajio', 'snapdeal', 'nykaa'],
    'Fintech & Banking': ['pay', 'bank', 'finance', 'wallet', 'money', 'loan', 'insurance', 'paytm', 'phonepe', 'razorpay', 'icici', 'hdfc', 'sbi', 'axis'],
    'Food & Delivery': ['food', 'restaurant', 'delivery', 'eat', 'kitchen', 'zomato', 'swiggy', 'blinkit', 'dunzo'],
    'Travel & Transport': ['travel', 'hotel', 'flight', 'cab', 'taxi', 'ride', 'tour', 'ticket', 'ola', 'uber', 'oyo', 'makemytrip', 'goibibo', 'redbus', 'irctc'],
    'Education': ['education', 'learn', 'study', 'course', 'academy', 'school', 'university', 'exam', 'byju', 'unacademy', 'vedantu'],
    'News & Media': ['news', 'media', 'times', 'express', 'post', 'daily', 'tv', 'channel', 'ndtv', 'zee', 'aaj tak'],
    'Technology & IT': ['tech', 'software', 'digital', 'web', 'app', 'cloud', 'data', 'infosys', 'tcs', 'wipro', 'zoho', 'freshworks'],
    'Government & Public': ['gov', 'nic', 'govt', 'ministry', 'department', 'uidai', 'epfo', 'gst']
}

for domain in sorted(all_domains):
    categorized = False
    domain_lower = domain.lower()
    
    for category, keywords in category_keywords.items():
        if any(kw in domain_lower for kw in keywords):
            categories[category].append(domain)
            categorized = True
            break
    
    if not categorized:
        if domain.endswith('.in') or '.in.' in domain:
            categories['Other .in domains'].append(domain)
        else:
            categories['Other Indian brands'].append(domain)

# Generate new indian_domains.py content
new_content = '''"""
Indian Trusted Domains - Comprehensive whitelist for Indian brands and services
Auto-generated from domain.csv dataset
"""

INDIAN_TRUSTED_DOMAINS = {
'''

for category, domains in categories.items():
    if domains:
        new_content += f"    # {category}\n"
        for domain in sorted(domains):
            new_content += f"    '{domain}',\n"
        new_content += "\n"

new_content += '''}\n
def is_indian_trusted_domain(url):
    """Check if URL is from a trusted Indian domain - EXACT domain match only"""
    from urllib.parse import urlparse
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname if parsed.hostname else ''
        hostname_lower = hostname.lower()
        
        # Check if hostname ENDS with the trusted domain (exact match or subdomain)
        for domain in INDIAN_TRUSTED_DOMAINS:
            if hostname_lower == domain or hostname_lower.endswith('.' + domain):
                return True
        return False
    except:
        return False

if __name__ == '__main__':
    # Test
    test_urls = [
        "https://www.flipkart.com/",
        "https://www.amazon.in/",
        "https://paytm.com/",
        "https://www.zomato.com/",
    ]
    
    print("Testing Indian Domain Recognition:")
    print("=" * 60)
    for url in test_urls:
        is_trusted = is_indian_trusted_domain(url)
        print(f"{url:<40} {'✓ TRUSTED' if is_trusted else '✗ NOT TRUSTED'}")
'''

# Save updated file
with open('indian_domains.py', 'w', encoding='utf-8') as f:
    f.write(new_content)

print(f"\n✓ Updated indian_domains.py")
print(f"\nTotal domains in whitelist: {len(all_domains)}")
print(f"  • New domains added: {len(all_domains - existing_domains)}")
print(f"  • Existing domains: {len(existing_domains)}")

print("\n" + "=" * 80)
print("✅ COMPLETED!")
print("=" * 80)
print("\nSummary by category:")
for category, domains in categories.items():
    if domains:
        print(f"  • {category}: {len(domains)} domains")

print(f"\n📁 File updated: indian_domains.py")
print(f"🔐 Total protected domains: {len(all_domains)}")
