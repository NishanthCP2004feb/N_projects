"""
Fixed app.py with proper integration of benign-focused model.
This version prioritizes the benign-focused model for accurate detection.
"""

from flask import Flask, render_template, request, jsonify
import joblib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load benign-focused detector (PRIMARY MODEL)
benign_detector = None
try:
    from benign_url_detector import BenignURLDetector
    benign_detector = BenignURLDetector()
    print("✓ Benign-focused detector loaded successfully")
except Exception as e:
    print(f"⚠ Warning: Could not load benign-focused detector: {e}")

# Load explanation module
try:
    from explanation import get_explanation
except ImportError:
    def get_explanation(url, prediction):
        return prediction, [f"URL classified as {prediction}"]

app = Flask(__name__)

# Load fallback models
main_model, main_vectorizer, main_label_encoder = None, None, None
lexical_model, lexical_label_encoder, lexical_features = None, None, None

try:
    main_model_path = "saved_model/url_threat_model.joblib"
    main_vectorizer_path = "saved_model/vectorizer.joblib"
    main_label_encoder_path = "saved_model/label_encoder.joblib"

    if os.path.exists(main_model_path):
        main_model = joblib.load(main_model_path)
        main_vectorizer = joblib.load(main_vectorizer_path)
        main_label_encoder = joblib.load(main_label_encoder_path)
        print("✓ Main TF-IDF model loaded")
except Exception as e:
    print(f"⚠ Warning: Could not load main model: {e}")

try:
    lexical_model_path = "lexical_model/lexical_model.joblib"
    lexical_label_encoder_path = "lexical_model/lexical_label_encoder.joblib"
    lexical_features_path = "lexical_model/lexical_features.joblib"

    if os.path.exists(lexical_model_path):
        lexical_model = joblib.load(lexical_model_path)
        lexical_label_encoder = joblib.load(lexical_label_encoder_path)
        lexical_features = joblib.load(lexical_features_path)
        print("✓ Lexical model loaded")
except Exception as e:
    print(f"⚠ Warning: Could not load lexical model: {e}")


@app.route('/')
def index():
    """Render the main page."""
    return render_template('index.html')


@app.route('/predict', methods=['POST'])
def predict():
    """
    Enhanced prediction using benign-focused model as primary.
    Falls back to other models if unavailable.
    """
    try:
        data = request.get_json()
        url = data.get('url', '').strip()

        if not url:
            return jsonify({
                'error': 'Please provide a URL',
                'prediction': 'error'
            }), 400

        # Strategy 1: Use benign-focused model (BEST ACCURACY)
        if benign_detector:
            result = benign_detector.predict(url, use_ensemble=True)
            prediction = result['prediction']
            confidence = result['confidence']
            
            # Get detailed explanation
            explanation = benign_detector.explain_prediction(url, result)
            
            # Format as list for consistency with old app
            explanation_list = explanation.split('\n')
            
            return jsonify({
                'prediction': prediction,
                'confidence': f"{confidence:.2%}",
                'explanation': explanation_list,
                'source': 'Benign-Focused Ensemble Model',
                'model_details': {
                    'rf_prediction': result['model_details']['rf_prediction'],
                    'rf_confidence': f"{result['model_details']['rf_confidence']:.2%}",
                    'gb_prediction': result['model_details']['gb_prediction'],
                    'gb_confidence': f"{result['model_details']['gb_confidence']:.2%}"
                }
            })

        # Strategy 2: Use main TF-IDF model
        elif main_model and main_vectorizer and main_label_encoder:
            url_vectorized = main_vectorizer.transform([url])
            prediction_encoded = main_model.predict(url_vectorized)[0]
            prediction = main_label_encoder.inverse_transform([prediction_encoded])[0]
            
            probabilities = main_model.predict_proba(url_vectorized)[0]
            confidence = max(probabilities)
            
            # Get explanation
            specific_type, explanation_list = get_explanation(url, prediction)
            
            return jsonify({
                'prediction': specific_type,
                'confidence': f"{confidence:.2%}",
                'explanation': explanation_list,
                'source': 'Main TF-IDF Model'
            })

        # Strategy 3: Use lexical model
        elif lexical_model and lexical_features:
            from urllib.parse import urlparse
            import re
            
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname if parsed_url.hostname else ''
            
            features = {
                'url_length': len(url),
                'num_dots': url.count('.'),
                'num_special_chars': len(re.findall(r'[^a-zA-Z0-9\./]', url)),
                'num_digits': sum(c.isdigit() for c in url),
                'num_subdomains': len(hostname.split('.')) - 2 if hostname else 0,
                'has_suspicious_keywords': 1 if any(kw in url.lower() for kw in ['login', 'verify', 'account', 'secure', 'password']) else 0,
                'uses_https': 1 if parsed_url.scheme == 'https' else 0,
                'is_ip': 1 if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname) else 0
            }
            
            import numpy as np
            feature_array = np.array([[features[col] for col in lexical_features]])
            
            prediction_encoded = lexical_model.predict(feature_array)[0]
            probabilities = lexical_model.predict_proba(feature_array)[0]
            
            # Decode prediction properly
            prediction = lexical_label_encoder.inverse_transform([prediction_encoded])[0]
            confidence = max(probabilities)
            
            specific_type, explanation_list = get_explanation(url, prediction)
            
            return jsonify({
                'prediction': specific_type,
                'confidence': f"{confidence:.2%}",
                'explanation': explanation_list,
                'source': 'Lexical Feature Model'
            })

        else:
            return jsonify({
                'error': 'No models available for prediction',
                'prediction': 'error'
            }), 500

    except Exception as e:
        print(f"Error during prediction: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            'error': str(e),
            'prediction': 'error'
        }), 500


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'models': {
            'benign_focused': benign_detector is not None,
            'main_tfidf': main_model is not None,
            'lexical': lexical_model is not None
        }
    })


if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("URL THREAT DETECTOR - ENHANCED WITH BENIGN-FOCUSED MODEL")
    print("=" * 70)
    print("\nModels loaded:")
    print(f"  • Benign-Focused Model: {'✓ Active' if benign_detector else '✗ Not loaded'}")
    print(f"  • Main TF-IDF Model: {'✓ Available' if main_model else '✗ Not loaded'}")
    print(f"  • Lexical Model: {'✓ Available' if lexical_model else '✗ Not loaded'}")
    print("\nStarting Flask application...")
    print("Available at: http://127.0.0.1:5000")
    print("\n" + "=" * 70 + "\n")
    
    app.run(debug=True, host='127.0.0.1', port=5000)
