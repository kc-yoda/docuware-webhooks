# docuware-webhooks
Example node express service to test DocuWare Webhooks with signature validation

## Known Issues with signature verification
If the you use any numeric fields then your signature may not validate. When minifying the JSON the decimal places can get set differently than what they are during DocuWares signature verification.

If you have Newtonsoft.Json available you may potentially be able to get serialization/deserialization to act the same as DocuWare.

## Initialize

run 'npm install' in the docuware-webhook-node directory

To run in development mode: run 'npm run dev'
To build the distribution: run 'npm run build'

### DocuWare webhooks for initial verification

Limit your initial template to one or two text fields, such as document type and status. This will ensure you have a viable JSON for testing the signature verification. Once you are able to validat the signature consistantly you can modify your webhook template to expand fields as desired and determine if any cause failure points such as including numeric fields for decimal money values. 
We have experienced issues with '5.30' becoming '5.3' in the JSON minification and then the signature is not valid.



