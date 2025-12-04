"""
Test institutional domains in Flask API
"""
import requests
import time

def test_institutional_urls():
    base_url = "http://127.0.0.1:5000/predict"
    
    test_cases = [
        ("https://www.ksit.ac.in/", "benign", "KSIT Academic (.ac.in)"),
        ("https://www.ksit.ACC.in/", "benign", "KSIT with uppercase ACC"),
        ("https://iitb.ac.in/", "benign", "IIT Bombay"),
        ("https://mit.edu/", "benign", "MIT (.edu)"),
        ("https://www.gov.in/", "benign", "India Government"),
        ("https://www.uidai.gov.in/", "benign", "UIDAI Government"),
        ("https://nta.ac.in/", "benign", "NTA Academic"),
        ("https://www.google.com/", "benign", "Google"),
        ("https://www.g00gle.com/", "phishing", "g00gle (typosquatting)"),
    ]
    
    print("=" * 80)
    print("TESTING INSTITUTIONAL DOMAIN DETECTION")
    print("=" * 80)
    
    # Wait for Flask to be ready
    print("\nWaiting for Flask server...")
    time.sleep(2)
    
    passed = 0
    failed = 0
    
    for url, expected, description in test_cases:
        try:
            response = requests.post(
                base_url,
                json={"url": url},
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                prediction = result.get('prediction', '').lower()
                confidence = result.get('confidence', 0)
                source = result.get('source', 'Unknown')
                
                status = "✅" if prediction == expected else "❌"
                if prediction == expected:
                    passed += 1
                else:
                    failed += 1
                
                print(f"\n{status} {description}")
                print(f"   URL: {url}")
                print(f"   Expected: {expected.upper()}")
                print(f"   Got: {prediction.upper()} ({confidence*100:.0f}% confidence)")
                print(f"   Source: {source}")
                
            else:
                print(f"\n❌ {description} - HTTP {response.status_code}")
                failed += 1
                
        except requests.exceptions.ConnectionError:
            print(f"\n❌ {description} - Connection refused (Flask not running?)")
            failed += 1
        except Exception as e:
            print(f"\n❌ {description} - Error: {e}")
            failed += 1
    
    print("\n" + "=" * 80)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 80)
    
    if failed == 0:
        print("\n✅ ALL INSTITUTIONAL DOMAINS DETECTED CORRECTLY!")
        print("✅ Academic domains (.ac.in, .edu) working")
        print("✅ Government domains (.gov.in) working")
        print("✅ Typosquatting detection still active")
    else:
        print(f"\n⚠️ {failed} tests failed")

if __name__ == "__main__":
    test_institutional_urls()
