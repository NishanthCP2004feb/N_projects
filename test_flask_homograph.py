"""
Test Flask app with g00gle.com (homograph attack)
"""
import requests
import time

# Give server a moment to start
time.sleep(2)

url = "http://127.0.0.1:5000/predict"
test_url = "https://www.g00gle.com"  # Homograph attack (0 instead of o)

print("=" * 80)
print("TESTING FLASK APP: g00gle.com (Homograph Attack)")
print("=" * 80)
print(f"\nTest URL: {test_url}")
print(f"Expected: PHISHING (not BENIGN)")
print()

try:
    response = requests.post(url, json={"url": test_url}, timeout=10)
    
    if response.status_code == 200:
        result = response.json()
        
        prediction = result.get('prediction', 'N/A')
        source = result.get('source', 'N/A')
        explanation = result.get('explanation', ['N/A'])
        
        print(f"✓ Server Response:")
        print(f"  Prediction: {prediction.upper()}")
        print(f"  Source: {source}")
        print(f"  Explanation: {explanation[0][:100]}")
        print()
        
        if prediction.lower() == 'phishing':
            print("✅ SUCCESS! Homograph attack correctly detected as PHISHING!")
        else:
            print(f"❌ FAILED! Expected PHISHING but got {prediction.upper()}")
    else:
        print(f"❌ HTTP Error: {response.status_code}")
        print(response.text)
        
except Exception as e:
    print(f"❌ Error: {e}")

print("=" * 80)
