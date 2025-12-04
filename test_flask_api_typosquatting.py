"""
Test the Flask API with typosquatting URLs
"""

import requests
import json

BASE_URL = "http://127.0.0.1:5000"

def test_api():
    print("=" * 80)
    print("TESTING FLASK API WITH TYPOSQUATTING DETECTION")
    print("=" * 80)
    
    # Test cases
    test_cases = [
        ("https://www.youtube.com", "benign", "Legitimate YouTube"),
        ("https://www.youtUbe.com", "phishing", "Case variation: youtUbe"),
        ("https://www.youTube.com", "phishing", "Case variation: youTube"),
        ("https://www.g00gle.com", "phishing", "Digit substitution: g00gle"),
        ("https://www.google.com", "benign", "Legitimate Google"),
        ("https://www.gooogle.com", "phishing", "Character repetition: gooogle"),
        ("https://www.FaceBook.com", "phishing", "Case variation: FaceBook"),
        ("https://www.facebook.com", "benign", "Legitimate Facebook"),
    ]
    
    print("\nTesting predictions via Flask API...")
    print("-" * 80)
    
    passed = 0
    failed = 0
    
    for url, expected, description in test_cases:
        try:
            response = requests.post(
                f"{BASE_URL}/predict",
                json={"url": url},
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                data = response.json()
                prediction = data.get('prediction', 'unknown')
                source = data.get('source', 'unknown')
                explanation = data.get('explanation', [])
                
                status = "✓ PASS" if prediction == expected else "✗ FAIL"
                if prediction == expected:
                    passed += 1
                else:
                    failed += 1
                
                print(f"\n{description}")
                print(f"  URL:        {url}")
                print(f"  Expected:   {expected}")
                print(f"  Predicted:  {prediction}")
                print(f"  Source:     {source}")
                print(f"  Status:     {status}")
                
                if explanation:
                    print(f"  Explanation: {explanation[0][:100]}...")
            else:
                print(f"\n{description}")
                print(f"  URL:    {url}")
                print(f"  ERROR:  HTTP {response.status_code}")
                failed += 1
        
        except Exception as e:
            print(f"\n{description}")
            print(f"  URL:    {url}")
            print(f"  ERROR:  {str(e)}")
            failed += 1
    
    print("\n" + "=" * 80)
    print(f"API TEST RESULTS: {passed} passed, {failed} failed out of {len(test_cases)} total")
    print("=" * 80)
    
    if failed == 0:
        print("\n✓ ALL API TESTS PASSED!")
    else:
        print(f"\n⚠ {failed} API test(s) failed.")

if __name__ == '__main__':
    print("\nMake sure the Flask app is running on http://127.0.0.1:5000")
    print("Waiting 2 seconds before testing...\n")
    
    import time
    time.sleep(2)
    
    test_api()
