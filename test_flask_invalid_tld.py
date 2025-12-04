"""
Test Flask API for Invalid TLD Detection
"""
import requests
import json
import time

def test_flask_invalid_tld():
    base_url = "http://127.0.0.1:5000/predict"
    
    # Wait for server to be ready
    time.sleep(2)
    
    test_cases = [
        # Valid TLDs
        ("https://www.ksit.ac.in/", "benign", "Valid .ac.in"),
        ("https://www.google.com/", "benign", "Valid .com"),
        ("https://www.mit.edu/", "benign", "Valid .edu"),
        
        # Invalid TLDs (typos)
        ("https://www.ksit.acc.in/", "phishing", "Invalid .acc.in"),
        ("https://www.google.comm/", "phishing", "Invalid .comm"),
        ("https://www.stanford.eduu/", "phishing", "Invalid .eduu"),
        ("https://www.paypal.govv/", "phishing", "Invalid .govv"),
    ]
    
    print("=" * 80)
    print("TESTING FLASK API - INVALID TLD DETECTION")
    print("=" * 80)
    
    passed = 0
    failed = 0
    
    for url, expected, description in test_cases:
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
                
                print(f"\n{status} - {description}")
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
        print("\n✅ ALL TESTS PASSED!")
        print("✅ Invalid TLD detection working in Flask API")
        print("✅ .acc, .comm, .eduu, .govv are now flagged as PHISHING")
    else:
        print(f"\n⚠️ {failed} tests failed")
    
    return failed == 0

if __name__ == "__main__":
    test_flask_invalid_tld()
