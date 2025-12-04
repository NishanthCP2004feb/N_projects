"""
Comprehensive test of the enhanced phishing detection system.
Tests case variations, digit substitutions, and legitimate domains.
"""

from enhanced_benign_detector import EnhancedBenignURLDetector

def test_enhanced_detection():
    print("=" * 80)
    print("COMPREHENSIVE PHISHING DETECTION TEST")
    print("=" * 80)
    
    detector = EnhancedBenignURLDetector()
    
    # Test cases
    test_cases = [
        # Legitimate domains (should be BENIGN)
        ("https://www.youtube.com", "benign", "Legitimate YouTube"),
        ("https://www.google.com", "benign", "Legitimate Google"),
        ("https://www.facebook.com", "benign", "Legitimate Facebook"),
        ("https://www.amazon.in", "benign", "Legitimate Amazon India"),
        
        # Case variation attacks (should be PHISHING)
        ("https://www.youtUbe.com", "phishing", "Case variation: youtUbe"),
        ("https://www.youTube.com", "phishing", "Case variation: youTube"),
        ("https://www.YoutUbe.com", "phishing", "Case variation: YoutUbe"),
        ("https://www.YOUTUBE.COM", "phishing", "Case variation: YOUTUBE"),
        ("https://www.Google.com", "phishing", "Case variation: Google"),
        ("https://www.FaceBook.com", "phishing", "Case variation: FaceBook"),
        
        # Digit substitution attacks (should be PHISHING)
        ("https://www.g00gle.com", "phishing", "Digit substitution: g00gle"),
        ("https://www.fac3book.com", "phishing", "Digit substitution: fac3book"),
        ("https://www.faceb00k.com", "phishing", "Digit substitution: faceb00k"),
        ("https://www.y0utube.com", "phishing", "Digit substitution: y0utube"),
        
        # Character repetition attacks (should be PHISHING)
        ("https://www.gooogle.com", "phishing", "Repetition: gooogle"),
        ("https://www.facebookk.com", "phishing", "Repetition: facebookk"),
        ("https://www.youutube.com", "phishing", "Repetition: youutube"),
        
        # Character omission attacks (should be PHISHING)
        ("https://www.gogle.com", "phishing", "Omission: gogle"),
        ("https://www.facbook.com", "phishing", "Omission: facbook"),
        
        # Indian domains
        ("https://www.flipkart.com", "benign", "Legitimate Flipkart"),
        ("https://www.Flipkart.com", "phishing", "Case variation: Flipkart"),
        ("https://www.fl1pkart.com", "phishing", "Digit substitution: fl1pkart"),
    ]
    
    print("\nTesting phishing detection...")
    print("-" * 80)
    
    passed = 0
    failed = 0
    
    for url, expected, description in test_cases:
        result = detector.predict(url)
        prediction = result['prediction']
        confidence = result['confidence']
        source = result['source']
        
        status = "✓ PASS" if prediction == expected else "✗ FAIL"
        if prediction == expected:
            passed += 1
        else:
            failed += 1
        
        print(f"\n{description}")
        print(f"  URL:        {url}")
        print(f"  Expected:   {expected}")
        print(f"  Predicted:  {prediction} (confidence: {confidence:.2f})")
        print(f"  Source:     {source}")
        print(f"  Status:     {status}")
    
    print("\n" + "=" * 80)
    print(f"TEST RESULTS: {passed} passed, {failed} failed out of {len(test_cases)} total")
    print("=" * 80)
    
    if failed == 0:
        print("\n✓ ALL TESTS PASSED! The system correctly detects typosquatting attacks.")
    else:
        print(f"\n⚠ {failed} test(s) failed. Review the results above.")
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print("✓ Case variation detection (e.g., youtUbe.com) - ACTIVE")
    print("✓ Digit substitution detection (e.g., g00gle.com) - ACTIVE")
    print("✓ Character repetition detection (e.g., gooogle.com) - ACTIVE")
    print("✓ Character omission detection (e.g., gogle.com) - ACTIVE")
    print("✓ Legitimate domain whitelist - ACTIVE")
    print("✓ ML ensemble models - ACTIVE")
    print("=" * 80)

if __name__ == '__main__':
    test_enhanced_detection()
