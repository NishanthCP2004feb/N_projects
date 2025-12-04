"""
Enhanced URL Threat Detector - Benign URL Detection
This module provides prediction using benign-focused models.
"""

import joblib
import numpy as np
import os
import re
from urllib.parse import urlparse

# Common legitimate TLDs and domains
LEGITIMATE_TLDS = {
    '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int',
    '.co.uk', '.ac.uk', '.gov.uk', '.com.au', '.gov.au',
    '.ca', '.de', '.fr', '.jp', '.cn', '.in', '.br'
}

LEGITIMATE_DOMAINS = {
    'google', 'youtube', 'facebook', 'twitter', 'instagram', 'linkedin',
    'microsoft', 'apple', 'amazon', 'netflix', 'wikipedia', 'github',
    'stackoverflow', 'reddit', 'yahoo', 'bing', 'outlook', 'gmail',
    'gitlab', 'coursera', 'udemy', 'khanacademy', 'spotify', 'dropbox',
    'onedrive', 'ebay', 'walmart', 'target', 'bbc', 'nytimes', 'cnn',
    'forbes', 'techcrunch', 'medium', 'wordpress', 'blogger', 'meesho',
    'flipkart', 'snapdeal', 'myntra', 'ajio', 'paytm', 'phonepe'
}

class BenignURLDetector:
    """
    Enhanced URL threat detector with focus on accurate benign URL detection.
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
            
            print(f"✓ Benign-focused models loaded from '{model_dir}'")
            
        except FileNotFoundError as e:
            print(f"✗ Error loading models: {e}")
            raise
    
    def extract_features(self, url):
        """Extract enhanced lexical features from URL."""
        features = {}
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname if parsed_url.hostname else ''
        
        # Basic URL features
        features['url_length'] = len(url)
        features['num_dots'] = url.count('.')
        features['num_hyphens'] = url.count('-')
        features['num_underscores'] = url.count('_')
        features['num_slashes'] = url.count('/')
        features['num_special_chars'] = len(re.findall(r'[^a-zA-Z0-9\./]', url))
        features['num_digits'] = sum(c.isdigit() for c in url)
        
        # Domain and subdomain features
        if hostname:
            domain_parts = hostname.split('.')
            features['num_subdomains'] = max(0, len(domain_parts) - 2)
            features['domain_length'] = len(hostname)
            features['has_www'] = 1 if hostname.startswith('www.') else 0
        else:
            features['num_subdomains'] = 0
            features['domain_length'] = 0
            features['has_www'] = 0
        
        # Suspicious keyword detection
        suspicious_keywords = [
            'login', 'verify', 'account', 'secure', 'password', 'update',
            'confirm', 'banking', 'paypal', 'signin', 'webscr', 'ebayisapi'
        ]
        features['has_suspicious_keywords'] = 1 if any(kw in url.lower() for kw in suspicious_keywords) else 0
        
        # Protocol features
        features['uses_https'] = 1 if parsed_url.scheme == 'https' else 0
        features['is_ip'] = 1 if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname) else 0
        
        # Legitimate domain indicators
        url_lower = url.lower()
        features['has_legitimate_tld'] = 1 if any(url_lower.endswith(tld) for tld in LEGITIMATE_TLDS) else 0
        features['has_known_domain'] = 1 if any(domain in hostname.lower() for domain in LEGITIMATE_DOMAINS) else 0
        
        # URL complexity and entropy features
        features['ratio_digits'] = features['num_digits'] / max(len(url), 1)
        features['ratio_special_chars'] = features['num_special_chars'] / max(len(url), 1)
        
        # Entropy
        char_freq = {}
        for char in url:
            char_freq[char] = char_freq.get(char, 0) + 1
        entropy = -sum((freq / len(url)) * np.log2(freq / len(url)) for freq in char_freq.values())
        features['url_entropy'] = entropy
        
        # Path and query features
        features['path_length'] = len(parsed_url.path)
        features['has_query'] = 1 if parsed_url.query else 0
        features['query_length'] = len(parsed_url.query) if parsed_url.query else 0
        features['has_fragment'] = 1 if parsed_url.fragment else 0
        
        # Shortened URLs
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly']
        features['is_shortened'] = 1 if any(short in hostname.lower() for short in shorteners) else 0
        
        # Consecutive patterns
        features['has_consecutive_dots'] = 1 if '..' in url else 0
        features['has_consecutive_slashes'] = 1 if '//' in url.replace('://', '') else 0
        
        return features
    
    def predict(self, url, use_ensemble=True):
        """
        Predict URL threat level using benign-focused models.
        
        Args:
            url: The URL to analyze
            use_ensemble: If True, uses both RF and GB models (safer)
        
        Returns:
            dict with 'prediction', 'confidence', and 'model_details'
        """
        # Extract features
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
            # Conservative approach: If either model says malicious, flag as malicious
            # This minimizes false positives (malicious shown as benign)
            if rf_label == 'malicious' or gb_label == 'malicious':
                final_prediction = 'malicious'
                confidence = max(rf_proba[rf_pred], gb_proba[gb_pred])
            else:
                final_prediction = 'benign'
                # Require high confidence from both models for benign
                confidence = min(rf_proba[rf_pred], gb_proba[gb_pred])
        else:
            # Use Random Forest prediction only
            final_prediction = rf_label
            confidence = rf_proba[rf_pred]
        
        return {
            'prediction': final_prediction,
            'confidence': float(confidence),
            'model_details': {
                'rf_prediction': rf_label,
                'rf_confidence': float(rf_proba[rf_pred]),
                'gb_prediction': gb_label,
                'gb_confidence': float(gb_proba[gb_pred]),
                'ensemble_used': use_ensemble
            }
        }
    
    def explain_prediction(self, url, prediction_result):
        """
        Explain why a URL was classified as benign or malicious.
        """
        features = self.extract_features(url)
        explanation = []
        
        if prediction_result['prediction'] == 'benign':
            explanation.append("✓ This URL appears to be BENIGN based on:")
            
            if features['has_known_domain']:
                explanation.append("  • Recognized legitimate domain")
            if features['has_legitimate_tld']:
                explanation.append("  • Uses common legitimate TLD")
            if features['uses_https']:
                explanation.append("  • Uses secure HTTPS protocol")
            if features['has_suspicious_keywords'] == 0:
                explanation.append("  • No suspicious keywords detected")
            if features['is_ip'] == 0:
                explanation.append("  • Uses domain name (not raw IP)")
            if features['is_shortened'] == 0:
                explanation.append("  • Not a URL shortener")
                
        else:
            explanation.append("⚠ This URL appears to be MALICIOUS based on:")
            
            if features['has_suspicious_keywords']:
                explanation.append("  • Contains suspicious keywords (login, verify, etc.)")
            if features['is_ip']:
                explanation.append("  • Uses raw IP address instead of domain")
            if features['is_shortened']:
                explanation.append("  • Uses URL shortening service")
            if features['has_consecutive_dots']:
                explanation.append("  • Contains consecutive dots (..)")
            if features['url_entropy'] > 4.5:
                explanation.append("  • High URL randomness/entropy")
            if features['num_subdomains'] > 3:
                explanation.append("  • Excessive number of subdomains")
            if not features['has_legitimate_tld']:
                explanation.append("  • Unusual or suspicious TLD")
        
        explanation.append(f"\nConfidence: {prediction_result['confidence']:.2%}")
        
        return "\n".join(explanation)


def test_detector():
    """Test the benign-focused detector with sample URLs."""
    print("=" * 70)
    print("TESTING BENIGN-FOCUSED URL DETECTOR")
    print("=" * 70)
    
    try:
        detector = BenignURLDetector()
        
        test_urls = [
            "https://www.google.com",
            "https://github.com/user/repo",
            "http://192.168.1.1/admin",
            "http://suspicious-login-verify.xyz/account",
            "https://www.microsoft.com/en-us/windows",
            "http://bit.ly/abc123"
        ]
        
        for url in test_urls:
            print(f"\n{'-' * 70}")
            print(f"URL: {url}")
            result = detector.predict(url)
            print(f"\nPrediction: {result['prediction'].upper()}")
            print(f"Confidence: {result['confidence']:.2%}")
            print("\n" + detector.explain_prediction(url, result))
        
        print(f"\n{'=' * 70}")
        
    except Exception as e:
        print(f"✗ Error during testing: {e}")


if __name__ == '__main__':
    test_detector()
