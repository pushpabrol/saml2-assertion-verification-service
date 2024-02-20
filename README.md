# SAML Assertion Validation Service

This Node.js service validates SAML assertions, verifies their signatures against an Identity Provider's (IdP) certificate, and extracts user attributes from valid assertions. It's designed to integrate with systems requiring SAML assertion validation, such as OAuth2 or custom authentication flows.

## Features

- Validates SAML assertion signatures using the IdP's public certificate.
- Extracts user attributes from valid SAML assertions.
- Configurable via environment variables for flexibility and security.
- Includes error handling for signature verification and XML parsing.

## Getting Started

These instructions will help you set up and run the service on your local machine for development and testing purposes.

### Prerequisites

- Node.js (version 12.x or higher recommended)
- npm (usually comes with Node.js)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/pushpabrol/saml2-assertion-verification-service.git
   cd saml2-assertion-verification-service
   ```

2. Install NPM packages:
   ```bash
   npm install
   ```

3. Set up environment variables by creating a `.env` file in the root directory of the project. Add the following content, adjusting the values to match your IdP's certificate and other configurations:
   ```env
   IDP_CERT=-----BEGIN CERTIFICATE-----\nMIID...YOUR_CERTIFICATE_HERE...\n-----END CERTIFICATE-----
   ```

### Running the Service

To start the service, run:

```bash
npm start
```

This will start the service on a default port (e.g., 3000). You can access the service at `http://localhost:3000`.

## Usage

To validate a SAML assertion, send a POST request to `/validate-saml` with the assertion as base64 encoded assertion in the json body. Ensure the request's `Content-Type` is set to `application/json`.

Example using `curl`:

```bash
curl -X POST http://localhost:3000/validate-saml-assertion \
     --header 'Content-Type: application/json' \
--data '{
    "assertion" : "PHNhbWw6Q...YW1sOkFzc2VydGlvbj4="
```

The service will respond with JSON containing the extracted user attributes if the assertion is valid, or an error message if not.

## Configuration

The service can be configured via environment variables defined in the `.env` file. Currently supported variables include:

- `IDP_CERT`: The IdP's public certificate for signature verification.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
```
