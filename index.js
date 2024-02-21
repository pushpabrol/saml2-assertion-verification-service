const express = require('express');
const xml2js = require('xml2js');
const xpath = require('xpath');
const { DOMParser } = require('xmldom');
const { SignedXml } = require('xml-crypto');
require('dotenv').config();

const attributeNameMapping = {
    emailaddress: 'email',
    Email: 'email',
    email: 'email',
    mail: 'email',
    displayname: 'displayName',
    name: 'name',
    givenname: 'giveName',
    firstname: 'givenName',
    firstName: 'givenName',
    lastname: 'familyName',
    lastName: 'familyName',
    surname: 'familyName',

    // Add other attribute mappings as needed
};

// Assume the IdP's public certificate is stored in 'idp-cert.pem'
//const idpCert = process.env.IDP_CERT;
const idpCert = process.env.IDP_CERT.replace(/\\n/g, '\n');

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
    try {
        const errorHandler = {
            warning: (msg) => { console.warn('Warning:', msg); throw new Error(msg) },
            error: (msg) => { console.warn('Error:', msg); throw new Error(msg) },
            fatalError: (msg) => { console.warn('Fatal Error:', msg); throw new Error(msg) },
        };
        const doc = new DOMParser({ errorHandler }).parseFromString(assertionXml);

        // Check for parsing errors
        const errors = doc.getElementsByTagName("parsererror");
        if (errors.length > 0) {
            console.error("Error parsing XML:", errors[0].textContent);
            return { "valid": false, "error": errors[0].textContent };
        }

        // Adjusted to handle XML with or without namespaces
        const select = xpath.useNamespaces({ "saml": "urn:oasis:names:tc:SAML:2.0:assertion", "ds": "http://www.w3.org/2000/09/xmldsig#" });

        // Handling XML with or without namespace by using local-name()
        const signature = select("//*[local-name()='Signature']", doc, true);
        if (!signature) {
            return { "valid": false, "error": 'No signature found in SAML Assertion' };
        }

        const sig = new SignedXml({ publicCert: cert });

        sig.loadSignature(signature.toString());
        if (!sig.checkSignature(assertionXml)) {
            console.log(sig.validationErrors);
            return { "valid": false, "error": 'Signature validation failed: ' + (sig.validationErrors ? sig.validationErrors.join(', ') : "") };
        }

        // Using local-name() function to ignore namespaces
        const issuer = select("//*[local-name()='Assertion']/*[local-name()='Issuer']/text()", doc).toString();
        if (!issuer) {
            return { "valid": false, "error": 'Assertion must contain an Issuer element' };
        }

        const audience = select("//*[local-name()='Assertion']//*[local-name()='Audience']/text()", doc).toString();
        if (audience !== "my_sp_samltestid_001" && audience !== "my-sp-samltestid-001") {
            return { "valid": false, "error": 'Assertion Audience does not match the token endpoint URL' };
        }

        const subject = select("//*[local-name()='Assertion']//*[local-name()='Subject']/*[local-name()='NameID']/text()", doc).toString();
        if (!subject) {
            return { "valid": false, "error": 'Assertion must contain a Subject element' };
        }

        // Additional validation logic remains unchanged...

        return { "valid": true };
    } catch (error) {
        console.error('Error during signature validation:', error.message);
        return { "valid": false, "error": error.message };
    }
}



function extractDataFromSAMLAssertion(assertionXml) {
    const doc = new DOMParser().parseFromString(assertionXml);
    
    // Detecting if the XML uses namespaces based on the 'xmlns' attribute presence
    const usesNamespaces = assertionXml.includes('xmlns');

    let select;
    if (usesNamespaces) {
        // Define namespace mappings if XML namespaces are detected
        select = xpath.useNamespaces({
            "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
            "ds": "http://www.w3.org/2000/09/xmldsig#"
        });
    } else {
        // Use default xpath select method without namespaces
        select = xpath.select;
    }


    const extractLastName = (fullName) => {
        const parts = fullName.split('/');
        const lastPart = parts[parts.length - 1];
        // Extract the last segment after the last '/' or the entire name if no '/' present
        return lastPart.split(':').pop();
    };

    const transformAttributeName = (originalName) => {
        const lastName = extractLastName(originalName);
        return attributeNameMapping[lastName.toLowerCase()] || lastName;
    };

    // Extract attributes
    let attributes = {};
    const attributeNodes = select("//saml:AttributeStatement/saml:Attribute | //AttributeStatement/Attribute", doc);

    attributeNodes.forEach(node => {
        const name = extractLastName(node.getAttribute('Name'));
        const transformedName = transformAttributeName(name);
        const valueNodes = select(".//saml:AttributeValue | .//AttributeValue", node);
        if (valueNodes.length > 0) {
            // Assuming single value for simplicity; extend as needed for multiple values
            attributes[transformedName] = valueNodes[0].textContent || valueNodes[0].nodeValue || "";
        }
    });

    const nameId = select("//saml:Subject/saml:NameID/text() | //Subject/NameID/text()", doc).toString();
    const issuer = select("//saml:Issuer/text() | //Issuer/text()", doc).toString();

    attributes["NameID"] = nameId
    attributes["issuer"] = issuer;
    return attributes;

}




