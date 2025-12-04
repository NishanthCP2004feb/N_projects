"""
Direct test of institutional domain detection (no Flask)
"""
from enhanced_benign_detector import EnhancedBenignURLDetector

def test_direct():
    print("=" * 80)
    print("DIRECT TEST - INSTITUTIONAL DOMAINS")
    print("=" * 80)
    
    detector = EnhancedBenignURLDetector('benign_focused_model')
    print("✓ Detector loaded\n")
    
    test_cases = [
        ("https://www.ksit.ac.in/", "benign", "KSIT Academic"),
        ("https://www.ksit.ACC.in/", "benign", "KSIT uppercase ACC"),
        ("https://mit.edu/", "benign", "MIT"),
        ("https://stanford.edu/", "benign", "Stanford"),
        ("https://www.gov.in/", "benign", "India Government"),
        ("https://usa.gov/", "benign", "USA Government"),
        ("https://www.g00gle.com/", "phishing", "g00gle typosquatting"),
    ]
    
    passed = 0
    failed = 0
    
    for url, expected, description in test_cases:
        result = detector.predict(url)
        prediction = result['prediction'].lower()
        confidence = result['confidence']
        source = result['source']
        
        status = "✅" if prediction == expected else "❌"
        if prediction == expected:
            passed += 1
        else:
            failed += 1
        
        print(f"{status} {description}")
        print(f"   URL: {url}")
        print(f"   Expected: {expected.upper()} | Got: {prediction.upper()} ({confidence*100:.0f}%)")
        print(f"   Source: {source}\n")
    
    print("=" * 80)
    print(f"Results: {passed}/{len(test_cases)} passed")
    print("=" * 80)

if __name__ == "__main__":
    test_direct()
