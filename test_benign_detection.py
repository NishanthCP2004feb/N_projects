"""
Comprehensive test suite for benign URL detection.
Tests the model's accuracy with real-world legitimate URLs.
"""

from benign_url_detector import BenignURLDetector
import pandas as pd

# Comprehensive list of legitimate/benign URLs
BENIGN_TEST_URLS = [
    # Major tech companies
    "https://www.google.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.amazon.com",
    "https://www.facebook.com",
    "https://www.twitter.com",
    "https://www.linkedin.com",
    "https://www.instagram.com",
    
    # Developer platforms
    "https://github.com/torvalds/linux",
    "https://stackoverflow.com/questions/tagged/python",
    "https://gitlab.com/gitlab-org/gitlab",
    
    # Educational
    "https://www.wikipedia.org/wiki/Machine_Learning",
    "https://www.coursera.org/learn/machine-learning",
    "https://www.khanacademy.org",
    
    # News and media
    "https://www.bbc.com/news",
    "https://www.nytimes.com",
    "https://www.cnn.com",
    
    # E-commerce
    "https://www.ebay.com",
    "https://www.walmart.com",
    "https://www.target.com",
    
    # Email services
    "https://mail.google.com",
    "https://outlook.live.com",
    
    # Cloud services
    "https://drive.google.com",
    "https://www.dropbox.com",
    "https://onedrive.live.com",
    
    # Government
    "https://www.usa.gov",
    "https://www.gov.uk",
    
    # Entertainment
    "https://www.netflix.com",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.spotify.com",
]

# Suspicious/Malicious URLs for comparison
MALICIOUS_TEST_URLS = [
    "http://192.168.1.1/admin",
    "http://phishing-login-verify.xyz/account",
    "http://suspicious-paypal-update.com/signin",
    "http://bit.ly/random123",
    "http://malware-download.tk/file.exe",
    "http://fake-bank-secure.info/login",
    "http://account-verify-now.biz/confirm",
]

def test_benign_url_detection():
    """
    Test the model's ability to correctly identify benign URLs.
    """
    print("=" * 80)
    print("BENIGN URL DETECTION TEST SUITE")
    print("=" * 80)
    
    # Load detector
    detector = BenignURLDetector()
    
    # Test benign URLs
    print("\n" + "=" * 80)
    print("TESTING LEGITIMATE/BENIGN URLS")
    print("=" * 80)
    
    benign_results = []
    for url in BENIGN_TEST_URLS:
        result = detector.predict(url, use_ensemble=True)
        benign_results.append({
            'url': url,
            'prediction': result['prediction'],
            'confidence': result['confidence']
        })
        
        status = "✓ PASS" if result['prediction'] == 'benign' else "✗ FAIL"
        print(f"\n{status}: {url}")
        print(f"  Prediction: {result['prediction'].upper()} (Confidence: {result['confidence']:.2%})")
    
    # Test malicious URLs
    print("\n" + "=" * 80)
    print("TESTING MALICIOUS URLS (Should NOT be detected as benign)")
    print("=" * 80)
    
    malicious_results = []
    for url in MALICIOUS_TEST_URLS:
        result = detector.predict(url, use_ensemble=True)
        malicious_results.append({
            'url': url,
            'prediction': result['prediction'],
            'confidence': result['confidence']
        })
        
        status = "✓ PASS" if result['prediction'] == 'malicious' else "✗ FAIL (FALSE POSITIVE)"
        print(f"\n{status}: {url}")
        print(f"  Prediction: {result['prediction'].upper()} (Confidence: {result['confidence']:.2%})")
    
    # Calculate statistics
    print("\n" + "=" * 80)
    print("TEST RESULTS SUMMARY")
    print("=" * 80)
    
    benign_df = pd.DataFrame(benign_results)
    malicious_df = pd.DataFrame(malicious_results)
    
    benign_correct = len(benign_df[benign_df['prediction'] == 'benign'])
    benign_total = len(benign_df)
    benign_accuracy = (benign_correct / benign_total) * 100
    
    malicious_correct = len(malicious_df[malicious_df['prediction'] == 'malicious'])
    malicious_total = len(malicious_df)
    malicious_accuracy = (malicious_correct / malicious_total) * 100
    
    false_positives = len(malicious_df[malicious_df['prediction'] == 'benign'])
    false_negatives = len(benign_df[benign_df['prediction'] == 'malicious'])
    
    print(f"\n✓ BENIGN URL Detection:")
    print(f"  Correctly identified: {benign_correct}/{benign_total} ({benign_accuracy:.1f}%)")
    print(f"  False negatives (benign marked as malicious): {false_negatives}")
    
    print(f"\n✓ MALICIOUS URL Detection:")
    print(f"  Correctly identified: {malicious_correct}/{malicious_total} ({malicious_accuracy:.1f}%)")
    print(f"  False positives (malicious marked as benign): {false_positives}")
    
    print(f"\n✓ Overall Accuracy: {(benign_correct + malicious_correct) / (benign_total + malicious_total) * 100:.1f}%")
    
    print("\n" + "=" * 80)
    print("CRITICAL METRIC: False Positive Rate")
    print("=" * 80)
    print(f"False Positive Rate: {(false_positives / malicious_total) * 100:.2f}%")
    print("(Lower is better - this shows malicious URLs incorrectly shown as benign)")
    
    # Show failed cases
    if false_negatives > 0:
        print("\n" + "=" * 80)
        print("BENIGN URLS INCORRECTLY FLAGGED AS MALICIOUS:")
        print("=" * 80)
        failed_benign = benign_df[benign_df['prediction'] == 'malicious']
        for _, row in failed_benign.iterrows():
            print(f"  • {row['url']}")
    
    if false_positives > 0:
        print("\n" + "=" * 80)
        print("⚠ WARNING: MALICIOUS URLS INCORRECTLY SHOWN AS BENIGN:")
        print("=" * 80)
        failed_malicious = malicious_df[malicious_df['prediction'] == 'benign']
        for _, row in failed_malicious.iterrows():
            print(f"  • {row['url']}")
    
    print("\n" + "=" * 80)
    
    # Save results to CSV
    all_results = pd.concat([benign_df, malicious_df])
    all_results.to_csv('benign_detection_test_results.csv', index=False)
    print("✓ Test results saved to 'benign_detection_test_results.csv'")
    print("=" * 80)


if __name__ == '__main__':
    test_benign_url_detection()
