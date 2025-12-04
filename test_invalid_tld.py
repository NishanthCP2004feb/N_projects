"""
Test Invalid TLD Detection
Tests that invalid TLDs like .acc (should be .ac) are caught
"""
from enhanced_benign_detector import EnhancedBenignURLDetector

def test_invalid_tld():
    print("=" * 80)
    print("TESTING INVALID TLD DETECTION")
    print("=" * 80)
    
    detector = EnhancedBenignURLDetector('benign_focused_model')
    print("✓ Detector loaded\n")
    
    test_cases = [
        # Valid TLDs - should be BENIGN
        ("https://www.ksit.ac.in/", "benign", "Valid: .ac.in (academic)"),
        ("https://www.mit.edu/", "benign", "Valid: .edu (education)"),
        ("https://www.gov.in/", "benign", "Valid: .gov.in (government)"),
        ("https://www.google.com/", "benign", "Valid: .com (commercial)"),
        ("https://www.ox.ac.uk/", "benign", "Valid: .ac.uk (UK academic)"),
        
        # Invalid TLDs - should be PHISHING
        ("https://www.ksit.acc.in/", "phishing", "Invalid: .acc.in (not .ac.in)"),
        ("https://ksit.aac.in/", "phishing", "Invalid: .aac.in (not .ac.in)"),
        ("https://www.google.comm/", "phishing", "Invalid: .comm (not .com)"),
        ("https://www.microsoft.nett/", "phishing", "Invalid: .nett (not .net)"),
        ("https://www.amazon.inn/", "phishing", "Invalid: .inn (not .in)"),
        ("https://www.facebook.orgg/", "phishing", "Invalid: .orgg (not .org)"),
        ("https://www.paypal.govv/", "phishing", "Invalid: .govv (not .gov)"),
        ("https://www.stanford.eduu/", "phishing", "Invalid: .eduu (not .edu)"),
    ]
    
    passed = 0
    failed = 0
    
    print(f"{'URL':<45} | {'Expected':<10} | {'Got':<10} | {'Conf':<5} | {'Description':<30} | {'Status':<6}")
    print("=" * 130)
    
    for url, expected, description in test_cases:
        result = detector.predict(url)
        prediction = result['prediction'].lower()
        confidence = result['confidence']
        source = result.get('source', 'Unknown')
        
        if prediction == expected:
            status = "✅ PASS"
            passed += 1
        else:
            status = "❌ FAIL"
            failed += 1
        
        print(f"{url:<45} | {expected.upper():<10} | {prediction.upper():<10} | {confidence*100:>4.0f}% | {description:<30} | {status}")
        if prediction != expected:
            print(f"   └─ Source: {source}")
    
    print("\n" + "=" * 130)
    print(f"Results: {passed} passed, {failed} failed out of {len(test_cases)} tests")
    print("=" * 130)
    
    if failed == 0:
        print("\n✅ ALL TESTS PASSED!")
        print("✅ Invalid TLD detection is working correctly!")
        print("✅ .acc, .comm, .nett, .inn, .orgg, .govv, .eduu are now flagged as PHISHING")
    else:
        print(f"\n⚠️ {failed} tests failed")
    
    return failed == 0

if __name__ == "__main__":
    success = test_invalid_tld()
    exit(0 if success else 1)
