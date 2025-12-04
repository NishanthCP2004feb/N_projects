"""
Test the Flask app API with various URLs
"""
import requests
import json

API_URL = "http://127.0.0.1:5000/predict"

test_cases = [
    # Benign URLs
    ("https://www.google.com", "benign"),
    ("https://www.amazon.com", "benign"),
    ("https://www.github.com", "benign"),
    ("https://www.wikipedia.org", "benign"),
    ("https://stackoverflow.com", "benign"),
    
    # Phishing URLs
    ("http://paypal-secure-login.com/verify-account", "phishing"),
    ("http://amazon-update.com/signin", "non-benign"),
    ("http://bank-secure-verify.net/login", "non-benign"),
    
    # Malware URLs
    ("http://suspicious-site.com/download.exe", "non-benign"),
    ("http://malicious-domain.ru/file.zip", "non-benign"),
    ("http://192.168.1.1/malware.dll", "non-benign"),
]

print("=" * 80)
print("TESTING FLASK APP API")
print("=" * 80)

correct = 0
total = 0

for url, expected_category in test_cases:
    try:
        response = requests.post(API_URL, json={"url": url}, timeout=10)
        if response.status_code == 200:
            result = response.json()
            prediction = result.get('prediction', '')
            explanation = result.get('explanation', [])
            source = result.get('source', '')
            
            # Check if prediction matches expectation
            if expected_category == "benign":
                is_correct = prediction == "benign"
            else:
                is_correct = prediction != "benign"
            
            status = "✓ CORRECT" if is_correct else "✗ WRONG"
            if is_correct:
                correct += 1
            total += 1
            
            print(f"\nURL: {url}")
            print(f"Expected: {expected_category}")
            print(f"Prediction: {prediction}")
            print(f"Source: {source}")
            print(f"Status: {status}")
            if prediction != 'benign':
                print(f"Explanation: {explanation[0] if explanation else 'N/A'}")
        else:
            print(f"\nURL: {url}")
            print(f"ERROR: HTTP {response.status_code}")
            total += 1
            
    except Exception as e:
        print(f"\nURL: {url}")
        print(f"ERROR: {e}")
        total += 1

print("\n" + "=" * 80)
print(f"RESULTS: {correct}/{total} correct ({100*correct/total:.1f}%)")
print("=" * 80)
