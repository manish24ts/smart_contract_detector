import os
import sys
import traceback
import flask
from flask import Flask, request, render_template, jsonify
from werkzeug.utils import secure_filename
import tempfile

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from smart_contract_detector import SmartContractVulnerabilityDetector

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

# Initialize the detector
detector = SmartContractVulnerabilityDetector()

# Attempt to load existing model, train if not available
try:
    model_loaded = detector.load_model()
    if not model_loaded:
        detector.train_model()
        detector.save_model()
except Exception as e:
    print(f"Error loading/training model: {e}")
    traceback.print_exc()
    detector.train_model()
    detector.save_model()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_contract():
    try:
        if 'file' in request.files:
            file = request.files['file']
            if file and file.filename.endswith('.sol'):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                try:
                    result = detector.analyze_contract(contract_file=filepath)
                    os.remove(filepath)
                    return jsonify(result)
                except Exception as e:
                    return jsonify({'error': str(e)}), 500
            else:
                return jsonify({'error': 'Please upload a .sol file'}), 400
        elif 'code' in request.form:
            code = request.form['code']
            if code.strip():
                try:
                    result = detector.analyze_contract(contract_code=code)
                    return jsonify(result)
                except Exception as e:
                    return jsonify({'error': str(e)}), 500
            else:
                return jsonify({'error': 'Please enter Solidity code'}), 400
        else:
            return jsonify({'error': 'No file or code provided'}), 400
    except Exception as e:
        print(f"Unexpected error: {e}")
        traceback.print_exc()
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
