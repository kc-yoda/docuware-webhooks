from flask import Flask, request, jsonify
from flask_restful import Api, Resource
import hashlib
import hmac
import os
import json
from datetime import datetime

app = Flask(__name__)
api = Api(app)

class Webhook(Resource):
    def post(self):
        print("Received a POST request to /webhooks/docuware/")
        # Get the request data
        data = request.get_json()
        print("Received Data:", data)
        if not data:
            return {'error': 'No data provided'}, 400

        print("Starting minification of data")
        # Minify the data to json string by getting the raw data 
        minified_data = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
        # Log the minified data for debugging
        print("Minified Data:", minified_data)
        
        print("Getting signature from headers")
        # Get the signature from headers
        signature = request.headers.get('x-docuware-signature')
        if not signature:
            return {'error': 'Signature header missing'}, 400
        
        # Log the received signature for debugging
        print("Received Signature:", signature)
        
        # Validate the signature
        validation_results = self.validate_signature(data, minified_data, signature)
        if not validation_results['valid']:
            return validation_results, 403
        
        # Process the webhook data
        self.process_webhook(data)
        
        return validation_results, 202

    def validate_signature(self, raw, payload, expected_signature):
        print("Validating signature")
        secret = os.environ["DW_PASSPHRASE"]  # Replace with your actual secret key
        print("Using secret for validation:", secret)
        # Compute the HMAC SHA-512 signature
        actual_signature = hmac.new(secret.encode('utf-8'), str(payload).encode('utf-8'), hashlib.sha512).hexdigest()
        print("Computed Signature:", actual_signature)
        # Compare the computed signature with the received signature
        valid = hmac.compare_digest(actual_signature, expected_signature)
        return { "message": f"Validation processed results at {datetime.now()} with the validation result: {valid}", "raw": raw, "payload": payload, "expectedsignature": expected_signature, "actualsignature": actual_signature, "valid": valid }

    def process_webhook(self, data):
        # Implement your webhook processing logic here
        print("Webhook received:", data)

api.add_resource(Webhook, '/webhooks/docuware')

@app.route('/')
def index():
    return { "version": "1.0", "message": "Docuware Webhook API", "language": "Python" }

if __name__ == '__main__':
    app.run(debug=True)