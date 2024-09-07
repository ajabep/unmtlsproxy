# Example

Just run:

```bash
unmtlsproxy --backend https://client.badssl.com --cert ./badssl.com-client.crt.pem --cert-key ./badssl.com-client_NOENCRYPTION.key.pem --listen 127.0.0.1:24658 --log-level debug --mode http --unsafe-key-log-path ./keylog
```

Wanna debug using Wireshark?
Add the `./keylog` file in wireshark and run:

```bash
unmtlsproxy --backend https://client.badssl.com --cert ./badssl.com-client.crt.pem --cert-key ./badssl.com-client_NOENCRYPTION.key.pem --listen 127.0.0.1:24658 --log-level debug --mode http --unsafe-key-log-path ./keylog
```
