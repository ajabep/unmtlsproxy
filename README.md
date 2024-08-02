# unmtlsproxy

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/ajabep/unmtlsproxy/badge)](https://securityscorecards.dev/viewer/?uri=github.com/ajabep/unmtlsproxy)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=ajabeporg_unmtlsproxy&metric=security_rating)](https://sonarcloud.io/summary/new_code?id=ajabeporg_unmtlsproxy)


un-MTLS proxy is a simple proxy service to remove the mutual TLS authentication to some services. This is useful when a tool is not supporting mTLS.

> ⚠️ **DO NOT RUN IT IN PRODUCTION** ⚠️
>
> This will kill the value added by mTLS.
>
> NEVER EVER USE IT AGAINST IN PRODUCTION
>
> It's not a tool for daily life, only a tool when nothing else is possible and is really required.
>
> Do NOT use it if you don't know EXACTLY what you are doing!

My use-case is during penetration testing when some tools are not supporting mTLS, but, be careful of:

1. What you are doing!
2. Which interface you are binding!
3. How may access this interface!

## How to install?

Just run:

```bash
go install github.com/ajabep/unmtlsproxy@latest
```

## How to use?

See in the `./example/` directory.

## How to define a proxy?

Multiple ways are possibles:

1. The classic environment variables works well!
2. Using `proxychains` shoudl also work.

## Changes from github.com/PaloAltoNetworks/mtlsproxy

1. Now, it removes the mTLS layer. Actually, all the TLS part is removed.
2. Added some options to ease the debug
3. The docker version is no longer available: Not useful for penetration testing and I don't want to encourage this to be used to expose a service.

## Known issues

* If you use an encrypted private key, the underlying lib is not able to decrypt it. The original software had the same issue. Have to fix it. Will do a day, probably.
* May return `local error: tls: no renegotiation`.
* If an "exotic" port is given together with a scheme, may return `Cannot guess the Scheme for port XXXX`.
