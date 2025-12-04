"""
Enhanced Benign URL Detector with Indian Domain Support
Prioritizes Indian trusted domains for accurate detection
"""

import joblib
import numpy as np
import os
import re
import math
from collections import Counter
from urllib.parse import urlparse
from indian_domains import INDIAN_TRUSTED_DOMAINS, GLOBAL_INSTITUTIONAL_DOMAINS, is_indian_trusted_domain

# Common legitimate TLDs and domains (global)
LEGITIMATE_TLDS = {
    '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int',
    '.co.uk', '.ac.uk', '.gov.uk', '.com.au', '.gov.au', '.edu.au', '.ac.au',
    '.ca', '.de', '.fr', '.jp', '.cn', '.in', '.br',
    # Indian TLDs - comprehensive
    '.co.in', '.org.in', '.net.in', '.gov.in', '.ac.in', '.edu.in', '.nic.in', '.res.in',
    # Academic TLDs worldwide
    '.ac', '.edu', '.ac.uk', '.ac.jp', '.ac.cn', '.ac.kr', '.ac.th', '.ac.id',
    '.ac.nz', '.ac.za', '.ac.il', '.ac.bd', '.ac.lk', '.ac.pk', '.ac.ae',
    # Government TLDs worldwide  
    '.gov', '.gov.in', '.gov.uk', '.gov.au', '.gov.cn', '.gov.sg', '.gov.ph',
    '.gov.my', '.gov.bd', '.gov.lk', '.gov.pk', '.gov.ae', '.nic.in'
}

LEGITIMATE_DOMAINS = {
    # Global domains
    'google', 'youtube', 'facebook', 'twitter', 'instagram', 'linkedin',
    'microsoft', 'apple', 'amazon', 'netflix', 'wikipedia', 'github',
    'stackoverflow', 'reddit', 'yahoo', 'bing', 'outlook', 'gmail',
    'gitlab', 'coursera', 'udemy', 'khanacademy', 'spotify', 'dropbox',
    'onedrive', 'ebay', 'walmart', 'target', 'bbc', 'nytimes', 'cnn',
    'forbes', 'techcrunch', 'medium', 'wordpress', 'blogger',
    # Indian domains
    'meesho', 'flipkart', 'snapdeal', 'myntra', 'ajio', 'paytm', 'phonepe',
    'zomato', 'swiggy', 'makemytrip', 'goibibo', 'ola', 'oyo', 'nykaa',
    'byjus', 'unacademy', 'hotstar', 'jiocinema', 'cred', 'bharatpe'
}

# Comprehensive list of valid TLDs, including common second-level country codes
VALID_TLD_SET = {
    # Generic TLDs
    '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int', '.info', '.biz',
    '.name', '.pro', '.aero', '.asia', '.cat', '.coop', '.jobs', '.mobi',
    '.museum', '.tel', '.travel', '.xxx', '.ac', '.ad', '.ae', '.af', '.ag',
    '.ai', '.al', '.am', '.ao', '.aq', '.ar', '.as', '.at', '.au', '.aw',
    '.ax', '.az', '.ba', '.bb', '.bd', '.be', '.bf', '.bg', '.bh', '.bi',
    '.bj', '.bm', '.bn', '.bo', '.br', '.bs', '.bt', '.bw', '.by', '.bz',
    '.ca', '.cc', '.cd', '.cf', '.cg', '.ch', '.ci', '.ck', '.cl', '.cm',
    '.cn', '.co', '.cr', '.cu', '.cv', '.cw', '.cx', '.cy', '.cz', '.de',
    '.dj', '.dk', '.dm', '.do', '.dz', '.ec', '.ee', '.eg', '.er', '.es',
    '.et', '.eu', '.fi', '.fj', '.fk', '.fm', '.fo', '.fr', '.ga', '.gd',
    '.ge', '.gf', '.gg', '.gh', '.gi', '.gl', '.gm', '.gn', '.gp', '.gq',
    '.gr', '.gs', '.gt', '.gu', '.gw', '.gy', '.hk', '.hm', '.hn', '.hr',
    '.ht', '.hu', '.id', '.ie', '.il', '.im', '.in', '.io', '.iq', '.ir',
    '.is', '.it', '.je', '.jm', '.jo', '.jp', '.ke', '.kg', '.kh', '.ki',
    '.km', '.kn', '.kp', '.kr', '.kw', '.ky', '.kz', '.la', '.lb', '.lc',
    '.li', '.lk', '.lr', '.ls', '.lt', '.lu', '.lv', '.ly', '.ma', '.mc',
    '.md', '.me', '.mg', '.mh', '.mk', '.ml', '.mm', '.mn', '.mo', '.mp',
    '.mq', '.mr', '.ms', '.mt', '.mu', '.mv', '.mw', '.mx', '.my', '.mz',
    '.na', '.nc', '.ne', '.nf', '.ng', '.ni', '.nl', '.no', '.np', '.nr',
    '.nu', '.nz', '.om', '.pa', '.pe', '.pf', '.pg', '.ph', '.pk', '.pl',
    '.pm', '.pn', '.pr', '.ps', '.pt', '.pw', '.py', '.qa', '.re', '.ro',
    '.rs', '.ru', '.rw', '.sa', '.sb', '.sc', '.sd', '.se', '.sg', '.sh',
    '.si', '.sk', '.sl', '.sm', '.sn', '.so', '.sr', '.ss', '.st', '.su',
    '.sv', '.sx', '.sy', '.sz', '.tc', '.td', '.tf', '.tg', '.th', '.tj',
    '.tk', '.tl', '.tm', '.tn', '.to', '.tr', '.tt', '.tv', '.tw', '.tz',
    '.ua', '.ug', '.uk', '.us', '.uy', '.uz', '.va', '.vc', '.ve', '.vg',
    '.vi', '.vn', '.vu', '.wf', '.ws', '.ye', '.yt', '.za', '.zm', '.zw',
    # Common second-level country TLDs
    '.co.uk', '.co.in', '.co.jp', '.co.kr', '.co.za', '.co.nz', '.co.au',
    '.ac.uk', '.ac.in', '.ac.jp', '.ac.kr', '.ac.th', '.ac.nz', '.ac.za',
    '.gov.uk', '.gov.in', '.gov.au', '.gov.sg', '.gov.ph', '.gov.my',
    '.edu.au', '.edu.in', '.edu.sg', '.edu.ph', '.edu.my', '.edu.pk',
    '.org.uk', '.org.in', '.org.au', '.org.nz', '.org.za',
    '.net.uk', '.net.in', '.net.au', '.net.nz',
    '.nic.in', '.res.in', '.gen.in', '.firm.in', '.ind.in'
}

MAX_TLD_PARTS = max(tld.count('.') for tld in VALID_TLD_SET)

# Country TLDs that require specific second-level identifiers (co, ac, gov, etc.)
COUNTRY_SECOND_LEVEL_WHITELIST = {
    '.in': {'co', 'ac', 'edu', 'gov', 'nic', 'res', 'gen', 'firm', 'ind', 'mil', 'net', 'org'},
    '.uk': {'co', 'ac', 'gov', 'mod', 'mil', 'nhs', 'police', 'org', 'net', 'me', 'sch', 'plc', 'ltd'},
    '.au': {'com', 'net', 'org', 'edu', 'gov', 'csiro', 'asn', 'id'},
    '.nz': {'co', 'ac', 'gov', 'net', 'org', 'maori', 'iwi', 'cri', 'geek'},
    '.za': {'co', 'ac', 'gov', 'org', 'net', 'edu', 'law', 'mil'},
    '.jp': {'co', 'ac', 'go', 'ne', 'or', 'ed'},
    '.kr': {'co', 'ac', 'go', 'ne', 'or', 're'},
}

# Suspicious patterns frequently used for fake second-level markers (.abc.in, etc.)
INVALID_SLD_PATTERNS = {'abc', 'aac', 'acc', 'xyz', 'fake', 'temp', 'demo', 'example', 'test'}

# Common typo TLD endings spotted in phishing kits
INVALID_TLD_PATTERNS = [
    '.acc.in', '.abc.in', '.aac.in', '.acc.uk', '.abc.uk', '.eduu', '.govv', '.comm',
    '.nett', '.orgg', '.inn', '.gov.inn', '.edu.inn', '.ac.inn'
]

STRUCTURED_TLDS = set(COUNTRY_SECOND_LEVEL_WHITELIST.keys())

class EnhancedBenignURLDetector:
    """
    Enhanced URL threat detector with strong Indian domain support.
    """
    
    def __init__(self, model_dir='benign_focused_model'):
        """Load the benign-focused models and supporting files."""
        self.model_dir = model_dir
        
        try:
            rf_model_path = os.path.join(model_dir, 'benign_focused_rf_model.joblib')
            gb_model_path = os.path.join(model_dir, 'benign_focused_gb_model.joblib')
            label_encoder_path = os.path.join(model_dir, 'benign_label_encoder.joblib')
            features_path = os.path.join(model_dir, 'benign_features.joblib')
            
            self.rf_model = joblib.load(rf_model_path)
            self.gb_model = joblib.load(gb_model_path)
            self.label_encoder = joblib.load(label_encoder_path)
            self.feature_columns = joblib.load(features_path)
            
            print(f"[+] Enhanced detector loaded from '{model_dir}'")
            
        except FileNotFoundError as e:
            print(f"[!] Error loading models: {e}")
            raise
    
    def extract_features(self, url):
        """Extract enhanced lexical features from URL - matches training script."""
        features = {}
        
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname if parsed_url.hostname else ''
            path = parsed_url.path if parsed_url.path else ''
            netloc = parsed_url.netloc if parsed_url.netloc else ''
            
            # Length features
            features['url_length'] = len(url)
            features['hostname_length'] = len(hostname)
            features['path_length'] = len(path)
            
            # Character counting
            features['digit_count'] = sum(c.isdigit() for c in url)
            features['letter_count'] = sum(c.isalpha() for c in url)
            features['special_char_count'] = len(re.findall(r'[^a-zA-Z0-9]', url))
            
            # Domain features
            features['subdomain_count'] = hostname.count('.') - 1 if hostname.count('.') > 0 else 0
            features['dots_in_url'] = url.count('.')
            features['hyphens_in_hostname'] = hostname.count('-')
            
            # Suspicious patterns
            features['has_ip_address'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', hostname) else 0
            features['has_at_symbol'] = 1 if '@' in url else 0
            features['has_double_slash'] = 1 if '//' in url.replace('://', '') else 0
            
            # Case variation detection (NEW FEATURE)
            features['has_mixed_case'] = 1 if netloc != netloc.lower() else 0
            features['uppercase_count'] = sum(1 for c in netloc if c.isupper())
            
            # Digit substitution patterns (NEW FEATURE)
            digit_subs = {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g'}
            features['has_digit_substitution'] = 1 if any(d in hostname for d in digit_subs.keys()) else 0
            
            # Character repetition (NEW FEATURE)
            import itertools
            max_repeat = max((len(list(g)) for k, g in itertools.groupby(hostname)), default=1)
            features['max_char_repeat'] = max_repeat
            features['has_suspicious_repeat'] = 1 if max_repeat >= 3 else 0
            
            # Entropy
            def calculate_entropy(s):
                if not s:
                    return 0
                p = Counter(s)
                length = float(len(s))
                return -sum((count/length) * math.log2(count/length) for count in p.values())
            
            features['url_entropy'] = calculate_entropy(url)
            features['hostname_entropy'] = calculate_entropy(hostname)
            
            # Path features
            features['path_slashes'] = path.count('/')
            features['query_length'] = len(parsed_url.query) if parsed_url.query else 0
            
            # TLD features
            tld_match = re.search(r'\.(com|net|org|edu|gov|in|co\.in|uk|au)$', hostname)
            features['has_common_tld'] = 1 if tld_match else 0
            
        except Exception as e:
            print(f"Error extracting features from URL: {url}")
            print(f"Error: {e}")
        
        return features
        features['has_consecutive_slashes'] = 1 if '//' in url.replace('://', '') else 0
        
        return features
    
    def levenshtein_distance(self, s1, s2):
        """Calculate Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self.levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def has_homograph_attack(self, url):
        """
        Detect typosquatting/homograph attacks:
        - Character substitution: g00gle.com (0→o)
        - Character repetition: gooogle.com (extra o)
        - Character omission: gogle.com (missing o)
        - Similar-looking chars: goog1e.com (1→l)
        - Case variations: youtUbe.com (mixed case as disguise)
        """
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname if parsed_url.hostname else ''
        hostname_lower = hostname.lower()
        netloc_original = parsed_url.netloc if parsed_url.netloc else ''
        
        # Known legitimate domains (exact match required)
        trusted_brands = {
            'google.com', 'facebook.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'twitter.com', 'instagram.com', 'linkedin.com', 'netflix.com', 'paypal.com',
            'ebay.com', 'yahoo.com', 'bing.com', 'github.com', 'reddit.com',
            'wikipedia.org', 'youtube.com', 'whatsapp.com', 'gmail.com', 'outlook.com',
            # Indian brands
            'flipkart.com', 'amazon.in', 'paytm.com', 'phonepe.com', 'zomato.com',
            'swiggy.com', 'meesho.com', 'myntra.com', 'snapdeal.com', 'makemytrip.com',
            'ola.com', 'oyo.com', 'byjus.com', 'irctc.co.in', 'icicibank.com',
            'hdfcbank.com', 'sbi.co.in', 'axisbank.com'
        }
        
        # Remove www prefix for comparison
        clean_hostname = hostname_lower.replace('www.', '')
        
        # EXACT MATCH: If it's a legitimate domain with correct lowercase, return False
        if clean_hostname in trusted_brands and netloc_original == netloc_original.lower():
            return False
        
        # CHECK FOR SUSPICIOUS CASE VARIATIONS
        # Legitimate sites use consistent lowercase domains
        # Mixed case like "youtUbe.com" is suspicious
        if netloc_original != netloc_original.lower():
            # Has uppercase letters in domain name - check if it matches a brand when lowercased
            if clean_hostname in trusted_brands:
                return True  # It's a case-variation attack!
        
        # Extract core domain (remove TLD)
        core_domain = clean_hostname
        for tld in ['.com', '.net', '.org', '.in', '.co.in', '.io', '.co', '.edu', '.gov']:
            if core_domain.endswith(tld):
                core_domain = core_domain[:-len(tld)]
                break
        
        # Character substitutions for homograph attacks (digit -> letter)
        substitutions = {
            '0': 'o', '1': 'l', '3': 'e', '4': 'a',
            '5': 's', '7': 't', '8': 'b', '9': 'g'
        }
        
        # Normalize domain (replace digits with similar letters)
        normalized_domain = core_domain
        for digit, letter in substitutions.items():
            normalized_domain = normalized_domain.replace(digit, letter)
        
        # If domain contains digits that could be substitutions, check directly
        has_suspicious_digits = any(digit in core_domain for digit in substitutions.keys())
        
        # Check against each trusted brand
        for trusted in trusted_brands:
            # Extract brand core (remove TLD from trusted)
            brand_core = trusted
            for tld in ['.com', '.net', '.org', '.in', '.co.in', '.io']:
                if brand_core.endswith(tld):
                    brand_core = brand_core[:-len(tld)]
                    break
            
            # Skip very short brands
            if len(brand_core) < 4:
                continue
            
            # DIRECT CHECK: If normalized domain matches brand exactly, it's a homograph attack
            if normalized_domain == brand_core and has_suspicious_digits:
                return True
            
            # Calculate Levenshtein distance with NORMALIZED domain
            distance = self.levenshtein_distance(normalized_domain, brand_core)
            
            # Typosquatting detection thresholds
            max_allowed_distance = max(1, len(brand_core) // 4)  # Allow 1 char difference per 4 chars
            
            # If distance is small (1-2 edits) and domains are similar length
            if distance > 0 and distance <= max_allowed_distance:
                length_ratio = len(normalized_domain) / len(brand_core)
                
                # Similar length (80-120% of original)
                if 0.8 <= length_ratio <= 1.2:
                    return True
            
            # Check for exact substring match (brand appears in domain)
            if len(brand_core) >= 5:
                if brand_core in normalized_domain and normalized_domain != brand_core:
                    return True
                if normalized_domain in brand_core and normalized_domain != brand_core:
                    return True
        
        return False
    
    def _match_valid_tld(self, hostname_lower):
        """Return the matched TLD plus the remaining domain parts."""
        if not hostname_lower:
            return None, []
        parts = [part for part in hostname_lower.split('.') if part]
        if not parts:
            return None, []
        max_depth = min(len(parts), MAX_TLD_PARTS)
        for depth in range(max_depth, 0, -1):
            candidate = '.' + '.'.join(parts[-depth:])
            if candidate in VALID_TLD_SET:
                return candidate, parts[:-depth]
        return None, parts

    def _has_invalid_structured_sld(self, matched_tld, domain_parts):
        """Validate second-level markers for country-code namespaces like .in and .uk."""
        if matched_tld not in STRUCTURED_TLDS or len(domain_parts) < 1:
            return False
        
        # For .in domains, both direct registrations (amazon.in) and structured (amazon.co.in) are valid
        # domain_parts contains all parts before the TLD (e.g., ['www', 'amazon'] for www.amazon.in)
        # We only care about the SLD - the part immediately before the TLD
        
        # If only one domain part (excluding subdomains), it's a direct registration - valid
        # e.g., amazon.in -> parts=['amazon'], flipkart.co.in -> parts=['flipkart', 'co']
        # e.g., www.amazon.in -> parts=['www', 'amazon'] - we check 'amazon' which is parts[-1]
        
        if len(domain_parts) == 1:
            # Direct registration (e.g., amazon.in)
            return False
        
        # Get the second-level domain (part immediately before TLD)
        sld = domain_parts[-1]
        
        # For .in, allow both direct registrations and structured ones
        if matched_tld == '.in':
            # If it's a known second-level domain marker, it must be valid
            allowed = COUNTRY_SECOND_LEVEL_WHITELIST.get(matched_tld, set())
            if sld in allowed:
                return False
            # Otherwise, it's a direct registration - also valid
            return False
        
        # For other structured TLDs (like .uk), enforce the whitelist
        allowed = COUNTRY_SECOND_LEVEL_WHITELIST.get(matched_tld, set())
        return sld not in allowed

    def has_invalid_tld(self, url):
        """
        Check if URL has an invalid or suspicious TLD.
        Returns True if TLD is invalid/suspicious.
        """
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname if parsed_url.hostname else ''
        hostname_lower = hostname.lower()
        
        if not hostname_lower:
            return False
        
        for invalid_pattern in INVALID_TLD_PATTERNS:
            if hostname_lower.endswith(invalid_pattern):
                return True
        
        matched_tld, domain_parts = self._match_valid_tld(hostname_lower)
        if not matched_tld:
            return True
        
        if self._has_invalid_structured_sld(matched_tld, domain_parts):
            return True
        
        if len(domain_parts) >= 2:
            sld = domain_parts[-1]
            if sld in INVALID_SLD_PATTERNS:
                return True
        
        return False
    
    def predict(self, url, use_ensemble=True):
        """
        Predict URL threat level with Indian domain priority.
        
        Args:
            url: The URL to analyze
            use_ensemble: If True, uses both RF and GB models
        
        Returns:
            dict with 'prediction', 'confidence', 'model_details', and 'source'
        """
        # PRIORITY 0: Check for invalid TLD (like .acc instead of .ac)
        if self.has_invalid_tld(url):
            return {
                'prediction': 'phishing',
                'confidence': 0.98,  # 98% confidence for invalid TLD
                'source': 'Invalid TLD Detection',
                'model_details': {
                    'rf_prediction': 'phishing',
                    'rf_confidence': 0.98,
                    'gb_prediction': 'phishing',
                    'gb_confidence': 0.98,
                    'ensemble_used': False,
                    'whitelist_match': False,
                    'invalid_tld': True
                }
            }
        
        # PRIORITY 1: Check for homograph/typosquatting attacks
        if self.has_homograph_attack(url):
            return {
                'prediction': 'phishing',
                'confidence': 0.95,  # 95% confidence
                'source': 'Homograph Attack Detection',
                'model_details': {
                    'rf_prediction': 'phishing',
                    'rf_confidence': 0.95,
                    'gb_prediction': 'phishing',
                    'gb_confidence': 0.95,
                    'ensemble_used': False,
                    'whitelist_match': False,
                    'homograph_detected': True
                }
            }
        
        # PRIORITY 2: Check if it's a trusted Indian domain
        if is_indian_trusted_domain(url):
            return {
                'prediction': 'benign',
                'confidence': 1.0,  # 100% confidence
                'source': 'Indian Trusted Domain List',
                'model_details': {
                    'rf_prediction': 'benign',
                    'rf_confidence': 1.0,
                    'gb_prediction': 'benign',
                    'gb_confidence': 1.0,
                    'ensemble_used': False,
                    'whitelist_match': True
                }
            }
        
        # PRIORITY 3: Use ML models
        features = self.extract_features(url)
        
        # Convert to array in correct order
        feature_array = np.array([[features[col] for col in self.feature_columns]])
        
        # Get predictions from both models
        rf_pred = self.rf_model.predict(feature_array)[0]
        rf_proba = self.rf_model.predict_proba(feature_array)[0]
        
        gb_pred = self.gb_model.predict(feature_array)[0]
        gb_proba = self.gb_model.predict_proba(feature_array)[0]
        
        # Decode predictions
        rf_label = self.label_encoder.inverse_transform([rf_pred])[0]
        gb_label = self.label_encoder.inverse_transform([gb_pred])[0]
        
        if use_ensemble:
            # Conservative approach
            if rf_label == 'malicious' or gb_label == 'malicious':
                final_prediction = 'malicious'
                confidence = max(rf_proba[rf_pred], gb_proba[gb_pred])
            else:
                final_prediction = 'benign'
                confidence = min(rf_proba[rf_pred], gb_proba[gb_pred])
        else:
            final_prediction = rf_label
            confidence = rf_proba[rf_pred]
        
        return {
            'prediction': final_prediction,
            'confidence': float(confidence),
            'source': 'ML Ensemble Model',
            'model_details': {
                'rf_prediction': rf_label,
                'rf_confidence': float(rf_proba[rf_pred]),
                'gb_prediction': gb_label,
                'gb_confidence': float(gb_proba[gb_pred]),
                'ensemble_used': use_ensemble,
                'whitelist_match': False
            }
        }
    
    def explain_prediction(self, url, prediction_result):
        """Explain why a URL was classified as benign or malicious."""
        # Check if it was whitelisted
        if prediction_result.get('source') == 'Indian Trusted Domain List':
            return f"✓ This URL is from a TRUSTED INDIAN BRAND\n  • Recognized as legitimate Indian e-commerce/fintech/service\n  • Automatically whitelisted for safety\n  • Confidence: 100.00%"
        
        if prediction_result.get('source') == 'Homograph Attack Detection':
            return f"⚠ This URL appears to be MALICIOUS based on:\n  • TYPOSQUATTING/HOMOGRAPH ATTACK detected\n  • Domain uses character substitution, case variation, or repetition\n  • Attempting to impersonate a legitimate brand\n  • Confidence: {prediction_result.get('confidence', 0.95)*100:.2f}%\n  • Source: {prediction_result.get('source')}"
        
        if prediction_result.get('source') == 'Invalid TLD Detection':
            return f"⚠ This URL appears to be MALICIOUS based on:\n  • INVALID or SUSPICIOUS TLD detected\n  • Domain uses fake or misspelled top-level domain\n  • Confidence: {prediction_result.get('confidence', 0.98)*100:.2f}%\n  • Source: {prediction_result.get('source')}"
        
        features = self.extract_features(url)
        explanation = []
        
        if prediction_result['prediction'] == 'benign':
            explanation.append("✓ This URL appears to be BENIGN based on:")
            
            if features.get('has_common_tld', 0):
                explanation.append("  • Uses common legitimate TLD")
            if features.get('has_ip_address', 1) == 0:
                explanation.append("  • Uses domain name (not raw IP)")
            if features.get('has_mixed_case', 1) == 0:
                explanation.append("  • Proper lowercase domain formatting")
            if features.get('has_digit_substitution', 1) == 0:
                explanation.append("  • No suspicious digit substitutions")
            if features.get('subdomain_count', 10) <= 2:
                explanation.append("  • Reasonable subdomain structure")
            if features.get('url_entropy', 10) < 4.5:
                explanation.append("  • Low URL randomness/entropy")
                
        else:
            explanation.append("⚠ This URL appears to be MALICIOUS based on:")
            
            if features.get('has_mixed_case', 0):
                explanation.append("  • Contains mixed case (potential typosquatting)")
            if features.get('has_digit_substitution', 0):
                explanation.append("  • Contains digit substitutions (e.g., 0 for o)")
            if features.get('has_suspicious_repeat', 0):
                explanation.append("  • Contains suspicious character repetition")
            if features.get('has_ip_address', 0):
                explanation.append("  • Uses raw IP address instead of domain")
            if features.get('has_double_slash', 0):
                explanation.append("  • Contains double slashes in suspicious location")
            if features.get('url_entropy', 0) > 4.5:
                explanation.append("  • High URL randomness/entropy")
            if features.get('subdomain_count', 0) > 3:
                explanation.append("  • Excessive number of subdomains")
            if not features.get('has_common_tld', 1):
                explanation.append("  • Unusual or suspicious TLD")
        
        explanation.append(f"\nConfidence: {prediction_result['confidence']:.2%}")
        explanation.append(f"Source: {prediction_result.get('source', 'Unknown')}")
        
        return "\n".join(explanation)


def test_indian_domains():
    """Test Indian domains with enhanced detector."""
    print("=" * 80)
    print("TESTING ENHANCED INDIAN DOMAIN DETECTOR")
    print("=" * 80)
    
    try:
        detector = EnhancedBenignURLDetector()
        
        test_urls = [
            # Indian e-commerce
            "https://www.meesho.com/",
            "https://www.meesho.com/products/shoes",
            "https://www.flipkart.com/",
            "https://www.myntra.com/",
            "https://www.snapdeal.com/",
            "https://www.ajio.com/",
            
            # Indian fintech
            "https://paytm.com/",
            "https://phonepe.com/",
            "https://cred.club/",
            
            # Indian services
            "https://www.zomato.com/",
            "https://www.swiggy.com/",
            "https://www.ola.com/",
            
            # International
            "https://www.amazon.in/",
            "https://www.google.com/",
            
            # Malicious
            "http://fake-meesho-login.xyz/",
            "http://phishing-paytm.com/verify"
        ]
        
        for url in test_urls:
            print(f"\n{'-' * 80}")
            print(f"URL: {url}")
            result = detector.predict(url)
            print(f"\nPrediction: {result['prediction'].upper()}")
            print(f"Confidence: {result['confidence']:.2%}")
            print(f"Source: {result['source']}")
            print("\n" + detector.explain_prediction(url, result))
        
        print(f"\n{'=' * 80}")
        
    except Exception as e:
        print(f"✗ Error during testing: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    test_indian_domains()
