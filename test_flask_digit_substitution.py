"""
Test Flask API for digit substitution typosquatting detection
"""
import requests
import json

def test_flask_api():
    base_url = "http://127.0.0.1:5000/predict"
    
    test_cases = [
        # Legitimate domains
        ("https://www.google.com/", "benign"),
        ("https://www.facebook.com/", "benign"),
        ("https://www.microsoft.com/", "benign"),
        ("https://www.flipkart.com/", "benign"),
        
        # Digit substitution attacks (0 for o)
        ("https://www.g00gle.com/", "phishing"),
        ("https://www.faceb00k.com/", "phishing"),
        ("https://www.micr0soft.com/", "phishing"),
        
        # Mixed digit attacks
        ("https://www.g0ogle.com/", "phishing"),
        ("https://www.fl1pkart.com/", "phishing"),
        
        # Character repetition
        ("http://www.gooogle.com/", "phishing"),
        ("http://www.facebookk.com/", "phishing"),
        
        # Character omission
        ("http://www.gogle.com/", "phishing"),
        ("http://www.facbook.com/", "phishing"),
    ]
    
    print("=" * 80)
    print("TESTING FLASK API - DIGIT SUBSTITUTION DETECTION")
    print("=" * 80)
    
    passed = 0
    failed = 0
    
    for url, expected in test_cases:
        try:
            response = requests.post(
                base_url,
                json={"url": url},
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                result = response.json()
                prediction = result.get('prediction', '').lower()
                confidence = result.get('confidence', 0)
                source = result.get('source', 'Unknown')
                
                status = "✅ PASS" if prediction == expected else "❌ FAIL"
                if prediction == expected:
                    passed += 1
                else:
                    failed += 1
                
                print(f"\n{status}")
                print(f"URL: {url}")
                print(f"Expected: {expected.upper()}")
                print(f"Got: {prediction.upper()} ({confidence*100:.0f}% confidence)")
                print(f"Source: {source}")
                
            else:
                print(f"\n❌ FAIL - HTTP {response.status_code}")
                print(f"URL: {url}")
                failed += 1
                
        except Exception as e:
            print(f"\n❌ ERROR testing {url}: {e}")
            failed += 1
    
    print("\n" + "=" * 80)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 80)
    
    if failed == 0:
        print("\n✅ ALL TESTS PASSED! Digit substitution detection is working correctly.")
    else:
        print(f"\n⚠️ {failed} tests failed. Please check the implementation.")
    
    return failed == 0

if __name__ == "__main__":
    test_flask_api()
