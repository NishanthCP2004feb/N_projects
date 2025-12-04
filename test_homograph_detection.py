"""
Test homograph attack detection
"""
from enhanced_benign_detector import EnhancedBenignURLDetector

print("=" * 80)
print("TESTING HOMOGRAPH/TYPOSQUATTING ATTACK DETECTION")
print("=" * 80)

detector = EnhancedBenignURLDetector()

# Test URLs with character substitution attacks
test_urls = [
    # Legitimate
    ("https://www.google.com/", "BENIGN"),
    ("https://www.facebook.com/", "BENIGN"),
    ("https://www.microsoft.com/", "BENIGN"),
    ("https://www.flipkart.com/", "BENIGN"),
    
    # Digit substitution (0 for o, 1 for i)
    ("https://www.g00gle.com/", "PHISHING"),
    ("https://www.faceb00k.com/", "PHISHING"),
    ("https://www.micr0soft.com/", "PHISHING"),
    ("https://www.fl1pkart.com/", "PHISHING"),
    
    # Character repetition (extra letters)
    ("http://www.gooogle.com/", "PHISHING"),
    ("http://www.facebookk.com/", "PHISHING"),
    ("http://www.microsofft.com/", "PHISHING"),
    ("http://www.flipkartt.com/", "PHISHING"),
    
    # Character omission (missing letters)
    ("http://www.gogle.com/", "PHISHING"),
    ("http://www.facbook.com/", "PHISHING"),
    ("http://www.micrsoft.com/", "PHISHING"),
    
    # Mixed attacks
    ("https://www.g0ogle.com/", "PHISHING"),
    ("https://www.facebok.com/", "PHISHING"),
    
    # Real phishing
    ("http://phishing-test-123.xyz/", "MALICIOUS"),
]

print("\nTesting URLs:\n")
print(f"{'URL':<45} | {'Expected':<10} | {'Detected':<12} | {'Conf':<6} | {'Status'}")
print("=" * 100)

passed = 0
failed = 0

for url, expected in test_urls:
    result = detector.predict(url)
    detected = result['prediction'].upper()
    confidence = result['confidence']
    
    # Check if detection matches expectation
    if expected in ["PHISHING", "MALICIOUS"]:
        status = "✅ PASS" if detected in ["PHISHING", "MALICIOUS"] else "❌ FAIL"
    else:
        status = "✅ PASS" if detected == expected else "❌ FAIL"
    
    if "✅" in status:
        passed += 1
    else:
        failed += 1
    
    icon = "🚨" if detected in ["PHISHING", "MALICIOUS"] else "✅"
    
    print(f"{icon} {url:<42} | {expected:<10} | {detected:<12} | {confidence:>5.0%} | {status}")

print("=" * 100)
print(f"\nResults: {passed} passed, {failed} failed")
print("=" * 80)
