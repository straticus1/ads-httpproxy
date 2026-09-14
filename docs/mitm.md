# HTTPS interception setup

Generate a dedicated CA with certificate-signing usage:

```sh
openssl req -x509 -newkey rsa:3072 -nodes -days 365 \
  -keyout ca.key -out ca.crt -subj '/CN=ADS Development Proxy CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'
chmod 600 ca.key
```

Configure `ca_cert: ./ca.crt` and `ca_key: ./ca.key`, then restart the proxy.
It signs a separate host certificate for each intercepted CONNECT destination.
If neither file is configured, the proxy generates an isolated ephemeral CA;
for reproducible client trust, supply persistent certificate files. Validation
rejects incomplete pairs, invalid keys, and certificates without CA signing usage.
The interception CA is separate from `quic_cert`/`quic_key`, which are server
certificates for the HTTP/3 gateway's hostname.

For one command, trust the CA explicitly:

```sh
curl --proxy http://localhost:8080 --cacert ca.crt https://example.com
bin/ads-dev request -url https://example.com -ca ca.crt
```

For system/browser trust, install `ca.crt`:

- Linux (Debian/Ubuntu): copy to `/usr/local/share/ca-certificates/ads-proxy.crt`
  and run `sudo update-ca-certificates`.
- macOS: import into the intended Keychain and set certificate trust, or use
  `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt`.
- Windows: import into the intended Trusted Root Certification Authorities
  store using Certificate Manager.
- Firefox may use its own certificate store; import the CA under Authorities.

Install only the public certificate in clients. Keep the private key on the
proxy host. Use a dedicated development trust store where possible, and remove
the CA when interception is no longer needed.
