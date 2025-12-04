"""
Test script to verify that benign URLs are correctly classified as benign
and malicious URLs are correctly classified as malicious/phishing/malware/defacement
"""

import joblib
import pandas as pd
from urllib.parse import urlparse
import re
import math
from collections import Counter
from explanation import get_explanation

# Load the advanced lexical model
model = joblib.load('advanced_lexical_model/advanced_lexical_model.joblib')
features_list = joblib.load('advanced_lexical_model/advanced_lexical_features.joblib')

def extract_advanced_lexical_features(url):
    """Extract features for prediction"""
    features = {col: 0 for col in features_list}

    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname if parsed_url.hostname else ''
        path = parsed_url.path if parsed_url.path else ''

        # Simple length-based features
        features['Querylength'] = len(url)
        features['urlLen'] = len(url)
        features['domainlength'] = len(hostname)
        features['pathLength'] = len(path)
        features['subDirLen'] = len(path.split('/')) - 1

        # Counting features
        features['NumberofDotsinURL'] = url.count('.')
        features['URL_DigitCount'] = sum(c.isdigit() for c in url)
        features['host_DigitCount'] = sum(c.isdigit() for c in hostname)
        features['URL_Letter_Count'] = sum(c.isalpha() for c in url)
        features['host_letter_count'] = sum(c.isalpha() for c in hostname)

        # Symbol counting
        features['SymbolCount_URL'] = len(re.findall(r'[^a-zA-Z0-9]', url))
        features['SymbolCount_Domain'] = len(re.findall(r'[^a-zA-Z0-9\.]', hostname))

        # Tokenization features
        domain_tokens = hostname.split('.')
        path_tokens = [token for token in path.split('/') if token]

        features['domain_token_count'] = len(domain_tokens) if hostname else 0
        features['path_token_count'] = len(path_tokens)

        if domain_tokens and any(domain_tokens):
            features['avgdomaintokenlen'] = sum(len(t) for t in domain_tokens) / len(domain_tokens)
            features['longdomaintokenlen'] = max(len(t) for t in domain_tokens)
        else:
            features['avgdomaintokenlen'] = 0
            features['longdomaintokenlen'] = 0

        if path_tokens:
            features['avgpathtokenlen'] = sum(len(t) for t in path_tokens) / len(path_tokens)
        else:
            features['avgpathtokenlen'] = 0

        # Character composition features
        features['charcompvowels'] = sum(1 for char in url.lower() if char in 'aeiou')
        features['charcompace'] = sum(1 for char in url.lower() if char in 'ace')

        # Longest consecutive digit sequence
        def get_ldl(s):
            digit_sequences = re.findall(r'\d+', s)
            return max(len(seq) for seq in digit_sequences) if digit_sequences else 0

        features['ldl_url'] = get_ldl(url)
        features['ldl_domain'] = get_ldl(hostname)
        features['ldl_path'] = get_ldl(path)

        # Character Continuity Rate
        alnum_count = sum(c.isalnum() for c in url)
        if len(url) > 0:
            features['CharacterContinuityRate'] = alnum_count / len(url)

        # Shannon Entropy
        def shannon_entropy(s):
            if not s: return 0
            p, lns = Counter(s), float(len(s))
            return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

        features['Entropy_URL'] = shannon_entropy(url)
        features['Entropy_Domain'] = shannon_entropy(hostname)

    except Exception as e:
        print(f"Error extracting features for URL '{url}': {e}")

    return pd.DataFrame([features], columns=features_list)


# Test URLs
test_urls = {
    'benign': [
        'https://www.google.com',
        'https://www.amazon.com',
        'https://www.github.com',
        'https://www.wikipedia.org',
        'https://www.microsoft.com',
        'https://stackoverflow.com',
        'https://www.youtube.com'
    ],
    'phishing': [
        'http://paypal-secure-login.com/verify-account',
        'http://amazon-update.com/signin',
        'http://bank-secure-verify.net/login'
    ],
    'malware': [
        'http://suspicious-site.com/download.exe',
        'http://malicious-domain.ru/file.zip',
        'http://192.168.1.1/malware.dll'
    ],
    'defacement': [
        'http://hacked-website.com/defaced.html',
        'http://pwned-site.org/h4ck3d'
    ]
}

print("=" * 80)
print("TESTING URL CLASSIFICATION")
print("=" * 80)

for category, urls in test_urls.items():
    print(f"\n{'='*80}")
    print(f"Testing {category.upper()} URLs:")
    print('='*80)
    
    for url in urls:
        try:
            parsed_url_obj = urlparse(url)
            hostname_check = parsed_url_obj.hostname if parsed_url_obj.hostname else ''
            
            # --- Heuristic: Well-known Domains ---
            well_known_domains = [
                'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
                'amazon.com', 'microsoft.com', 'apple.com', 'wikipedia.org', 'linkedin.com',
                'github.com', 'stackoverflow.com', 'reddit.com', 'netflix.com', 'ebay.com',
                'yahoo.com', 'bing.com', 'adobe.com', 'paypal.com', 'dropbox.com',
                'github.io', 'salesforce.com', 'zoom.us', 'twitch.tv', 'office.com'
            ]
            
            is_well_known = False
            for domain in well_known_domains:
                if hostname_check.endswith(domain) or hostname_check == domain:
                    final_type = 'benign'
                    explanation = [f"This is a well-known legitimate domain ({domain})."]
                    is_well_known = True
                    break
            
            if not is_well_known:
                # Extract features and predict
                features = extract_advanced_lexical_features(url)
                prediction = model.predict(features)[0]
                prediction_lower = str(prediction).lower()
                
                # Get explanation
                if prediction_lower == 'benign':
                    final_type = 'benign'
                    explanation = ["The URL appears to be safe based on our analysis."]
                else:
                    final_type, explanation = get_explanation(url, prediction_lower)
            
            # Check if prediction is correct
            if category == 'benign':
                status = "✓ CORRECT" if final_type == 'benign' else "✗ WRONG"
            else:
                status = "✓ CORRECT" if final_type != 'benign' else "✗ WRONG"
            
            print(f"\nURL: {url}")
            print(f"Expected: {category}")
            if not is_well_known:
                print(f"Model prediction: {prediction}")
            print(f"Final classification: {final_type}")
            print(f"Status: {status}")
            if final_type != 'benign':
                print(f"Explanation: {'; '.join(explanation)}")
            
        except Exception as e:
            print(f"\nURL: {url}")
            print(f"ERROR: {e}")

print("\n" + "=" * 80)
print("Testing complete!")
print("=" * 80)
