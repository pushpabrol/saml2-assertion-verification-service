const express = require('express');
const xml2js = require('xml2js');
const xpath = require('xpath');
const { DOMParser } = require('xmldom');
const { SignedXml } = require('xml-crypto');
const fs = require('fs');

// Assume the IdP's public certificate is stored in 'idp-cert.pem'
const idpCert = fs.readFileSync('idp-cert.pem', 'utf8');

const app = express();
const port = 3001;

app.use(express.json());



app.post('/validate-saml-assertion', async (req, res) => {
    const assertionXmlBase64 = req.body.assertion;
    if (!assertionXmlBase64) {
        return res.status(400).send('Assertion is required');
    }

    // Decode the Base64-encoded SAML Assertion
    const samlAssertionXml = Buffer.from(assertionXmlBase64, 'base64').toString('utf-8');

    try {
        // Verify Signature
        const data = validateSamlAssertion(samlAssertionXml, idpCert);
        if (!data.valid) {
            return res.status(200).json(data);
        }

        // Assuming validation passes, extract user attributes
        const attributes = extractDataFromSAMLAssertion(samlAssertionXml);

        // Return extracted attributes
        res.json({ ...attributes, ...data });
    } catch (error) {
        console.error('Error validating SAML assertion:', error);
        res.status(500).json({ valid: false, error: error });
    }
});


app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});


// Helper function to validate the SAML Assertion signature and do other checks
function validateSamlAssertion(assertionXml, cert) {
    console.log("*****");
    console.log(cert);
    try {
        const errorHandler = {
            warning: (msg) =>  { console.warn('Warning:', msg); throw new Error(msg)},
            error: (msg) => { console.warn('Error:', msg); throw new Error(msg)},
            fatalError: (msg) => { console.warn('Fatal Error:', msg); throw new Error(msg)},
          };
        const doc = new DOMParser({errorHandler}).parseFromString(assertionXml);
        // Check for parsing errors
        const errors = doc.getElementsByTagName("parsererror");
        console.log(errors)
        console.log("*************************");
        console.log(errors.length);
        if (errors.length > 0) {
            console.error("Error parsing XML:", errors[0].textContent);
            return { "valid": false, "error": errors[0].textContent };
        }
        const select = xpath.useNamespaces({ "saml": "urn:oasis:names:tc:SAML:2.0:assertion", "ds": "http://www.w3.org/2000/09/xmldsig#" });

        // Use an XPath expression to correctly handle the namespace and find the Signature element
        const signature = select("//ds:Signature", doc, true);
        if (!signature) {
            return { "valid": false, "error": new Error('No signature found in SAML Assertion') };
        }

        const sig = new SignedXml({ publicCert: cert });

        // You must manually provide the node for signature validation
        sig.loadSignature(signature.toString());
        if (!sig.checkSignature(assertionXml)) {
            console.log(sig.validationErrors);
            return { "valid": false, "error": new Error('Signature validation failed: ' + (sig.validationErrors ? sig.validationErrors.join(', ') : "")) };
        }

        // Validate <Issuer> element
        const issuer = select("/saml:Assertion/saml:Issuer/text()", doc).toString();
        if (!issuer) {
            return { "valid": false, "error": new Error('Assertion must contain an Issuer element') };
        }

        // Validate <Audience>
        const audience = select("/saml:Assertion/saml:Conditions/saml:AudienceRestriction/saml:Audience/text()", doc).toString();
        if (audience !== "my-sp-samltestid-001") {
            return { "valid": false, "error": new Error('Assertion Audience does not match the token endpoint URL') };
        }

        // Validate <Subject> element
        const subject = select("/saml:Assertion/saml:Subject/saml:NameID/text()", doc).toString();
        if (!subject) {
            return { "valid": false, "error": new Error('Assertion must contain a Subject element') };
        }

        // Validate NotOnOrAfter and NotBefore in <Conditions>
        const conditions = select("/saml:Assertion/saml:Conditions", doc)[0];
        const notOnOrAfter = conditions.getAttribute('NotOnOrAfter');
        const notBefore = conditions.getAttribute('NotBefore');
        const now = new Date();
        //if (new Date(notOnOrAfter) < now || new Date(notBefore) > now) {
        // throw new Error('Assertion is not currently valid');
        //}

        // Validate <SubjectConfirmationData>
        const confirmationData = select("/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData", doc)[0];
        if (!confirmationData) {
            return { "valid": false, "error": new Error('SubjectConfirmationData is required for bearer assertions') };
        }
        //   if (confirmationData.getAttribute('Recipient') !== tokenEndpointUrl) {
        //     throw new Error('Recipient in SubjectConfirmationData does not match the token endpoint URL');
        //   }
        const confirmationNotOnOrAfter = confirmationData.getAttribute('NotOnOrAfter');
        //if (new Date(confirmationNotOnOrAfter) < now) {
        //   throw new Error('Assertion confirmation data has expired');
        // }


        return { "valid": true };
    } catch (error) {
        // Catch and handle errors thrown by checkSignature
        console.error('Error during signature validation:', error.message);
        // Handle the error as appropriate
        return { "valid": false, "error": error.message };
    }
}

function extractDataFromSAMLAssertion(assertionXml) {
    const doc = new DOMParser().parseFromString(assertionXml);
    const select = xpath.useNamespaces({ "saml": "urn:oasis:names:tc:SAML:2.0:assertion" });

    // Extracting the NameID which often contains the username or email
    const nameId = select("/saml:Assertion/saml:Subject/saml:NameID/text()", doc).toString();

    // Example of extracting an attribute value (e.g., email)
    const email = select("//saml:AttributeStatement/saml:Attribute[@Name='EmailAddress']/saml:AttributeValue/text()", doc).toString();

    const userId = select("//saml:AttributeStatement/saml:Attribute[@Name='UserID']/saml:AttributeValue/text()", doc).toString();

    // You can extract other attributes similarly
    const firstName = select("//saml:AttributeStatement/saml:Attribute[@Name='FirstName']/saml:AttributeValue/text()", doc).toString();
    const lastName = select("//saml:AttributeStatement/saml:Attribute[@Name='LastName']/saml:AttributeValue/text()", doc).toString();

    // Return the extracted data as an object
    return {
        nameId,
        email,
        userId,
        firstName,
        lastName,
        // Add other attributes as needed
    };
}