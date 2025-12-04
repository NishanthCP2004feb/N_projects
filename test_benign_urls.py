"""
Test script to verify benign URL classification improvements
"""

import requests
import json

# Flask API URL
API_URL = "http://127.0.0.1:5000/predict"

# Test URLs - all should be classified as benign
test_benign_urls = [
    # Educational institutions
    "https://www.ksit.ac.in",
    "https://www.mit.edu",
    "https://www.stanford.edu",
    "https://www.ox.ac.uk",
    "https://www.iitb.ac.in",
    
    # Government sites
    "https://www.gov.uk",
    "https://www.india.gov.in",
    
    # Well-known sites
    "https://www.google.com",
    "https://www.github.com",
    "https://www.wikipedia.org",
    
    # Other legitimate sites
    "https://www.bbc.com",
    "https://www.cnn.com",
    "https://www.nytimes.com",
]

print("=" * 80)
print("TESTING BENIGN URL CLASSIFICATION")
print("=" * 80)

correct = 0
total = len(test_benign_urls)

for url in test_benign_urls:
    try:
        response = requests.post(API_URL, json={"url": url}, timeout=10)
        
        if response.status_code == 200:
            result = response.json()
            prediction = result.get('prediction', 'unknown')
            explanation = result.get('explanation', [])
            source = result.get('source', 'N/A')
            
            is_correct = prediction == 'benign'
            status = "✓ CORRECT" if is_correct else "✗ WRONG"
            
            if is_correct:
                correct += 1
            
            print(f"\nURL: {url}")
            print(f"Prediction: {prediction}")
            print(f"Status: {status}")
            print(f"Source: {source}")
            if not is_correct:
                print(f"Explanation: {'; '.join(explanation)}")
        else:
            print(f"\nURL: {url}")
            print(f"ERROR: HTTP {response.status_code}")
            
    except Exception as e:
        print(f"\nURL: {url}")
        print(f"ERROR: {e}")

print("\n" + "=" * 80)
print(f"RESULTS: {correct}/{total} correct ({100*correct/total:.1f}%)")
print("=" * 80)
