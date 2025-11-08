## Current Certificates

- **privkey.pem**: Private key (4096-bit RSA)
- **fullchain.pem**: Self-signed certificate
- **Common Name (CN)**: webhook.timeherenow.com
- **Validity**: 365 days from creation date
- **Created**: November 7, 2025

## Regenerating Certificates

To regenerate the certificates (e.g., when they expire), run:

```bash
openssl req -x509 -newkey rsa:4096 \
  -keyout selfcerts/privkey.pem \
  -out selfcerts/fullchain.pem \
  -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/OU=Department/CN=webhook.timeherenow.com"
```

## Usage

The application automatically loads these certificates from `src/app.js`:

```javascript
const httpsOptions = {
  key: fs.readFileSync(path.join(__dirname, '../selfcerts/privkey.pem')),
  cert: fs.readFileSync(path.join(__dirname, '../selfcerts/fullchain.pem'))
};
```

## Security Notes

## Trusting the Certificate

To avoid browser warnings during local development:

### Linux
```bash
sudo cp selfcerts/fullchain.pem /usr/local/share/ca-certificates/timeherenow.crt
sudo update-ca-certificates
```

### macOS
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain selfcerts/fullchain.pem
```

### Windows
Import `fullchain.pem` into the "Trusted Root Certification Authorities" store via certmgr.msc
