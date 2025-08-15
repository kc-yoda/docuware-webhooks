import Router, { Request, Response } from 'express';
import crypto from 'crypto';


const docuware = Router();
const secretkey =  process.env.DW_PASSPHRASE || "";



docuware.get("/", (req: Request, res: Response) => {    
    console.info(`DocuWare webhook processed GET request from ${req.ip}`)
    res.send({state: 'invalid request', version: '0.1', expected: 'POST'});
});

docuware.post("/", (req: Request, res: Response) => {
    console.info(`DocuWare webhook processed request from ${req.ip}`);

    let validationResult = verifyHMAC(req, res, Buffer.from(JSON.stringify(req.body, (key: string, value: any) => {
            if (typeof value === 'number') {
                console.debug(`Minifying number value: ${value}`);
                // Minify number values to 2 decimal places
                return  Number(value.toFixed(2)); // Convert to fixed decimal places and then back to a number
            }
            return value;
        }), 'utf-8'));

    res.status(202).send({ message: validationResult?.message, raw: req.body, expectedsignature: validationResult?.expectedsignature, actualsignature: validationResult?.actualsignature, payload: validationResult?.payload });
});

function verifyHMAC(req: Request, res: Response, buf: Buffer, test?: boolean) : { message: string, raw?: string, expectedsignature?: string, actualsignature?: string, payload?: string, valid?: boolean} | null
{
    //shared function so we can call from middleware or from a request so that we can return JSON object with details about validation
    
     const docsig = (Array.isArray(req.headers['x-docuware-signature']) ? req.headers['x-docuware-signature'][0] : req.headers['x-docuware-signature'] as string);

    if (docsig)
    {
        console.info(`[Validation] Evaluating docuware signature ${docsig}`);
        
        let bufferStr = JSON.stringify(JSON.parse(buf.toString())); //minify

        if (test) bufferStr = bufferStr.replace("\"NET_AMOUNT\":578", "\"NET_AMOUNT\":578.00"); // ensure that NET_AMOUNT is always 2 decimal places

        console.debug(`Buffer string to validate: ${bufferStr}`);

        let newBuffer = Buffer.from(bufferStr, 'utf8');
        let keyBuffer = Buffer.from(secretkey, 'utf8');

        let hmac = crypto.createHmac('sha512', keyBuffer);
        hmac.update(newBuffer); 
        let generatedHmac = hmac.digest('hex');

        return {message: `Validation processed results at ${new Date()} with the validation result: ${generatedHmac === docsig}`, raw: buf.toString(), expectedsignature: docsig, actualsignature: generatedHmac, payload: bufferStr, valid: (generatedHmac === docsig)};
    }
    else
    {
        console.debug(`No docuware signature included`);
         return {message: `Validation processed results at ${new Date()} with the validation result: NO_SIGNATURE_INCLUDED`};
    }

    return null;
}

export function verification(req: Request, res: Response, buf: Buffer) {
    // this function gets called as middleware 
    let validationResult = verifyHMAC(req, res, buf);
    if (validationResult && validationResult.valid)
    {
        console.info(validationResult.message);
        console.info(`Raw: ${validationResult.raw}`);
        console.info(`Payload: ${validationResult.payload}`);
        console.info(`Expected: ${validationResult.expectedsignature}`);
        console.info(`Actual: ${validationResult.actualsignature}`);
        return true;
    }
    else if (validationResult) 
    {
         let results: object[] = [];
        results.push({ message: validationResult.message, raw: buf.toString(), expectedsignature: validationResult.expectedsignature, actualsignature: validationResult.actualsignature, payload: validationResult.payload });
        validationResult = verifyHMAC(req, res, buf, true);
        results.push({ message: validationResult?.message, raw: buf.toString(), expectedsignature: validationResult?.expectedsignature, actualsignature: validationResult?.actualsignature, payload: validationResult?.payload });

        console.info("----------------------------------------------------------------------------------------------------------------------");
        console.info(results);
        console.info("----------------------------------------------------------------------------------------------------------------------");

        console.info(validationResult?.message);
        console.info(`Raw: ${validationResult?.raw}`);
        console.info(`Payload: ${validationResult?.payload}`);
        console.info(`Expected: ${validationResult?.expectedsignature}`);
        console.info(`Actual: ${validationResult?.actualsignature}`);
        res.status(403).send(buf.toString());
        return res.status(403).send(buf.toString()); 
    }
    else 
    {
        return res.status(403).send(buf.toString())
    }
}

export default docuware;
