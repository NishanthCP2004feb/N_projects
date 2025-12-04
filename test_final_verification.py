"""
Final verification test - All typosquatting detection
Tests digit substitution, character repetition, and character omission
"""
from enhanced_benign_detector import EnhancedBenignURLDetector

def test_all_attacks():
    print("=" * 80)
    print("FINAL VERIFICATION - ALL TYPOSQUATTING ATTACKS")
    print("=" * 80)
    
    # Load detector
    detector = EnhancedBenignURLDetector('benign_focused_model')
    print("✓ Enhanced detector loaded\n")
    
    test_cases = [
        # Legitimate domains - should be BENIGN
        ("https://www.google.com/", "benign", "Legitimate Google"),
        ("https://www.facebook.com/", "benign", "Legitimate Facebook"),
        ("https://www.microsoft.com/", "benign", "Legitimate Microsoft"),
        ("https://www.flipkart.com/", "benign", "Legitimate Flipkart"),
        
        # DIGIT SUBSTITUTION ATTACKS - should be PHISHING
        ("https://www.g00gle.com/", "phishing", "Digit Attack: 0→o (g00gle)"),
        ("https://www.faceb00k.com/", "phishing", "Digit Attack: 0→o (faceb00k)"),
        ("https://www.micr0soft.com/", "phishing", "Digit Attack: 0→o (micr0soft)"),
        ("https://www.g0ogle.com/", "phishing", "Digit Attack: 0→o (g0ogle)"),
        ("https://www.fl1pkart.com/", "phishing", "Digit Attack: 1→l (fl1pkart)"),
        
        # CHARACTER REPETITION ATTACKS - should be PHISHING
        ("http://www.gooogle.com/", "phishing", "Repetition: gooogle"),
        ("http://www.facebookk.com/", "phishing", "Repetition: facebookk"),
        ("http://www.microsofft.com/", "phishing", "Repetition: microsofft"),
        
        # CHARACTER OMISSION ATTACKS - should be PHISHING
        ("http://www.gogle.com/", "phishing", "Omission: gogle"),
        ("http://www.facbook.com/", "phishing", "Omission: facbook"),
        ("http://www.micrsoft.com/", "phishing", "Omission: micrsoft"),
        
        # MIXED ATTACKS - should be PHISHING
        ("https://www.facebok.com/", "phishing", "Mixed: facebok (omit e)"),
    ]
    
    passed = 0
    failed = 0
    failed_tests = []
    
    print(f"{'URL':<45} | {'Expected':<10} | {'Got':<10} | {'Conf':<5} | {'Test Type':<30} | {'Status':<6}")
    print("=" * 130)
    
    for url, expected, description in test_cases:
        result = detector.predict(url)
        prediction = result['prediction'].lower()
        confidence = result['confidence']
        source = result.get('source', 'Unknown')
        
        # Check if it matches expected
        if prediction == expected:
            status = "✅ PASS"
            passed += 1
        else:
            status = "❌ FAIL"
            failed += 1
            failed_tests.append({
                'url': url,
                'expected': expected,
                'got': prediction,
                'confidence': confidence,
                'description': description,
                'source': source
            })
        
        print(f"{url:<45} | {expected.upper():<10} | {prediction.upper():<10} | {confidence*100:>4.0f}% | {description:<30} | {status}")
    
    print("\n" + "=" * 130)
    print(f"Results: {passed} passed, {failed} failed out of {len(test_cases)} tests")
    print("=" * 130)
    
    if failed > 0:
        print("\n⚠️ FAILED TESTS:")
        for i, test in enumerate(failed_tests, 1):
            print(f"\n{i}. {test['description']}")
            print(f"   URL: {test['url']}")
            print(f"   Expected: {test['expected'].upper()}")
            print(f"   Got: {test['got'].upper()} ({test['confidence']*100:.0f}% confidence)")
            print(f"   Source: {test['source']}")
    else:
        print("\n✅ ALL TESTS PASSED!")
        print("✅ Digit substitution detection: WORKING")
        print("✅ Character repetition detection: WORKING")
        print("✅ Character omission detection: WORKING")
        print("✅ All typosquatting attacks are now detected correctly!")
    
    return failed == 0

if __name__ == "__main__":
    success = test_all_attacks()
    exit(0 if success else 1)
