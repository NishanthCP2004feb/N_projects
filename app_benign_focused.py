"""
Enhanced Flask application with benign-focused URL detection.
This version integrates the new benign-focused models for better accuracy.
"""

from flask import Flask, render_template, request, jsonify
import joblib
import os
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import the benign-focused detector
try:
    from benign_url_detector import BenignURLDetector
    benign_detector = BenignURLDetector()
    print("✓ Benign-focused detector loaded successfully")
except Exception as e:
    print(f"⚠ Warning: Could not load benign-focused detector: {e}")
    benign_detector = None

# Import existing modules
try:
    from explanation import get_explanation
except ImportError:
    def get_explanation(url, prediction):
        return "basic_explanation", ["URL classification completed."]

app = Flask(__name__)

# Load existing models as fallback
main_model, main_vectorizer, main_label_encoder = None, None, None

try:
    main_model_path = "saved_model/url_threat_model.joblib"
    main_vectorizer_path = "saved_model/vectorizer.joblib"
    main_label_encoder_path = "saved_model/label_encoder.joblib"

    if os.path.exists(main_model_path):
        main_model = joblib.load(main_model_path)
        main_vectorizer = joblib.load(main_vectorizer_path)
        main_label_encoder = joblib.load(main_label_encoder_path)
        print("✓ Main model loaded successfully")
    else:
        print(f"⚠ Warning: Main model not found at '{main_model_path}'")
except Exception as e:
    print(f"⚠ Warning: Could not load main model: {e}")


@app.route('/')
def index():
    """Render the main page."""
    return render_template('index.html')


@app.route('/predict', methods=['POST'])
def predict():
    """
    Enhanced prediction endpoint using benign-focused model.
    Falls back to main model if benign-focused model is unavailable.
    """
    try:
        data = request.get_json()
        url = data.get('url', '').strip()

        if not url:
            return jsonify({
                'error': 'Please provide a URL',
                'prediction': 'error'
            }), 400

        # Primary: Use benign-focused model
        if benign_detector:
            result = benign_detector.predict(url, use_ensemble=True)
            prediction = result['prediction']
            confidence = result['confidence']
            model_details = result['model_details']
            
            # Get explanation
            explanation = benign_detector.explain_prediction(url, result)
            
            # Format response
            response = {
                'prediction': prediction,
                'confidence': f"{confidence:.2%}",
                'explanation': explanation,
                'model_used': 'benign_focused',
                'model_details': {
                    'rf_prediction': model_details['rf_prediction'],
                    'rf_confidence': f"{model_details['rf_confidence']:.2%}",
                    'gb_prediction': model_details['gb_prediction'],
                    'gb_confidence': f"{model_details['gb_confidence']:.2%}",
                    'ensemble': model_details['ensemble_used']
                }
            }
            
            return jsonify(response)

        # Fallback: Use main model
        elif main_model and main_vectorizer and main_label_encoder:
            url_vectorized = main_vectorizer.transform([url])
            prediction_encoded = main_model.predict(url_vectorized)[0]
            prediction = main_label_encoder.inverse_transform([prediction_encoded])[0]
            
            # Get probabilities
            probabilities = main_model.predict_proba(url_vectorized)[0]
            confidence = max(probabilities)
            
            # Get explanation
            _, explanation_points = get_explanation(url, prediction)
            explanation = "\n".join(explanation_points)
            
            response = {
                'prediction': prediction,
                'confidence': f"{confidence:.2%}",
                'explanation': explanation,
                'model_used': 'main_tfidf'
            }
            
            return jsonify(response)

        else:
            return jsonify({
                'error': 'No models available for prediction',
                'prediction': 'error'
            }), 500

    except Exception as e:
        print(f"Error during prediction: {e}")
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
            'main_model': main_model is not None
        }
    })


@app.route('/api/test-benign', methods=['POST'])
def test_benign_urls():
    """
    Test endpoint for batch benign URL detection.
    Accepts a list of URLs and returns predictions for all.
    """
    try:
        data = request.get_json()
        urls = data.get('urls', [])
        
        if not urls or not isinstance(urls, list):
            return jsonify({
                'error': 'Please provide a list of URLs'
            }), 400
        
        if not benign_detector:
            return jsonify({
                'error': 'Benign-focused detector not available'
            }), 503
        
        results = []
        for url in urls:
            result = benign_detector.predict(url.strip(), use_ensemble=True)
            results.append({
                'url': url,
                'prediction': result['prediction'],
                'confidence': f"{result['confidence']:.2%}"
            })
        
        # Calculate statistics
        benign_count = sum(1 for r in results if r['prediction'] == 'benign')
        malicious_count = len(results) - benign_count
        
        return jsonify({
            'results': results,
            'summary': {
                'total': len(results),
                'benign': benign_count,
                'malicious': malicious_count
            }
        })
    
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500


if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("ENHANCED URL THREAT DETECTOR - BENIGN-FOCUSED")
    print("=" * 70)
    print("\nStarting Flask application...")
    print("Available at: http://127.0.0.1:5000")
    print("\nEndpoints:")
    print("  • POST /predict - Single URL prediction")
    print("  • POST /api/test-benign - Batch URL testing")
    print("  • GET /health - Health check")
    print("\n" + "=" * 70 + "\n")
    
    app.run(debug=True, host='127.0.0.1', port=5000)
