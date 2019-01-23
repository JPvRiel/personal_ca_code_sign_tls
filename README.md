# Personal X509 certificates for code signing and TLS authentication testing

TL;DR: This project uses bash shell scripts and OpenSSL to setup a small Personal CA to issue code signing and TLS localhost certificates. A personal CA is used instead of simple self-signed certs because recent Chrome and Firefox browsers take exception to using self-signed certs for TLS authentication, even when the self-signed cert is included in the browser trust store.

Possible alternatives include running your own personal CA software such as [xca](https://github.com/chris2511/xca), or [tinyca](https://opsec.eu/src/tinyca/) (but seems un-maintained), etc.

## Overview

For local use, self-signed certificates used to be a quick and useful alternative to the overhead (and possbile cost) involved in obtaining 3rd party CA signed certs. However:

- NSS (Network Security Services) used by Chrome and Firefox no longer trust a certificate as a CA for issuing TLS certificates when it also includes X509v3 extended key usage attributes.
- Even when "Any Extended Key Usage" is included in the self-signed cert, as per RFC 5280, NSS won't allow the cert to be used for TLS authentication.

An alternate approach is to run your own minimal separate CA root authority to sign certificates with specific purposes for TLS authentication or code signing. 

Since a minimal CA hierarchy is used, certificates for specific purposes can be issued:

- Code signing cert (e.g. sign local powershell scripts)
- Local TLS client and server (e.g. test on `localhost` address)

### Code signing

#### Powershell digital signatures

A common convenience and work-around when developing powershell scripts may be:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Nonetheless, the `Set-AuthenticodeSignature` can sign the script or powershell module with a certificate that has both the 'digital signature' key usage and the 'code signing' extended key usage attributes set.

The code signing certificate needs to included in the "Trusted Publishers" certificate store container along with the CA being included in the "Trusted Root Certification Authorities" (or the 3rd-Party and Intermediary CA containers might work as well depending on the CA that signed the code singing cert).

Public CA's do offer code signing certificates.

#### Windows executable signatures

[SignTool.exe (Sign Tool)](https://docs.microsoft.com/en-us/dotnet/framework/tools/signtool-exe) can be used to digitally sign an executable.

Windows Defender Application Control can leverage code singing certificates. See
[Use code signing to simplify application control for classic Windows applications](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/use-code-signing-to-simplify-application-control-for-classic-windows-applications)

#### Linux secure boot and executable digital signatures and hashes

Due to UEFI superceding BIOS for trusted boot protection against malware and rootkits, OS kernel boot binaries are typically signed. Linux distro's often have their boot-loaders signed by a CA. `pesign` caters for advanced Linux users who intend running secure boot with custom complied kernels or modules and this leverages a code singing certificate.

As per [Does linux support signed binaries?](https://security.stackexchange.com/questions/138651/does-linux-support-signed-binaries), features to digitaly singing executables on Linux hasn't been overly popular. But various efforts like the Integrity Measurement Architecture (IMA) and (EVM) are progressing to extend the protection of secure boot beyond just the initial UEFI boot-loader. 

Related:

- [Ubuntu Wiki: SecureBoot](https://wiki.ubuntu.com/UEFI/SecureBoot)
- [Ubuntu Blog: How to sign things for Secure Boot](https://blog.ubuntu.com/2017/08/11/how-to-sign-things-for-secure-boot)
- [RedHat: Signing Kernel Modules for Secure Boot](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/Kernel_Administration_Guide/sect-signing-kernel-modules-for-secure-boot.html)
- [OpenSUSE SDB:IMA EVM](https://en.opensuse.org/SDB:Ima_evm)
- [Linux Kernel Integrity](https://kernsec.org/wiki/index.php/Linux_Kernel_Integrity)
- [Extending Linux Executable Logging With The Integrity Measurement Architecture](https://www.fireeye.com/blog/threat-research/2016/11/extending_linux_exec.html)

As per SUSE docs:

> IMA cares about the actual file content while EVM cares about the metadata

#### Linux deb and rpm package distribution digital signatures

Ubuntu/Debian apt (`.deb`) and "Enterprise Linux" (RedHat) (`.rpm`) doesn't use X509 certificates and hierarchical PKI certificate authorities to sign packages. Instead, GPG (GNU Privacy Guard), which follows OpenPGP standards that are "web-of-trust" based, is used. See [SecureApt](https://wiki.debian.org/SecureApt) whereby distributions like Debian and Ubuntu use PGP keys to sign the release packages.

It would be possible to use the same RSA private key and install the public key (not the certificate) as trusted in order to sign and validate locally developed and packaged install files.

As packages update binaries, in practice they'd also need to update kernel based integrity checking features that might be used (i.e. IMA/EVM), otherwise integrity checks would fail after updates.

### TLS certificate authentication

#### Background to certificate key usage with Chrome and Firefox

Chrome (tested with v71) leverages NSS. NSS does not seem to accept TLS server authentication extended key usage if the certificate is also a CA and simply gives a generic `NET::ERR_CERT_INVALID` error.

As per [Why does curl/NSS encryption library not allow a CA with the extended key usage by SEC_ERROR_INADEQUATE_CERT_TYPE?](https://security.stackexchange.com/questions/176177/why-does-curl-nss-encryption-library-not-allow-a-ca-with-the-extended-key-usage?), self-signed certificates can be problematic because implementations like NSS implement checks with a strict interpretation of RFC 5280's section, "4.2.1.12. Extended Key Usage". As per the RFC, "Extended Key Usage" is restricted as follows:

> In general, this extension will appear only in end entity certificates. [...]
> 
> If a CA includes extended key usages to satisfy such applications, but does not wish to restrict usages of the key, the CA can include the special keyPurposeID anyExtendedKeyUsage. [...]
> 
> If a certificate contains both a key usage extension and an extended key usage extension, then both extensions MUST be processed independently and the certificate MUST only be used for a purpose consistent with both extensions.

Even when testing with `anyExtendedKeyUsage`, Chrome and NSS did not accept the certificate for server authentication despite EKUs `serverAuth` and `anyExtendedKeyUsage` being present and compatible with `digitalSignature` key usage. Note, there's no apparent EKU that's consistent with `keyCertSign` key usage.

As of Firefox 64, it outright does not accept self signed certificates and provides a much clearer `MOZILLA_PKIX_ERROR_SELF_SIGNED_CERT` error message.

#### Insecure localhost testing

While chromium/chrome will allow and treat `http://localhost` as a secure origin (as per [Prefer Secure Origins For Powerful New Features](http://www.chromium.org/Home/chromium-security/prefer-secure-origins-for-powerful-new-features)), this doesn't allow for testing TLS functionality with `https://localhost`.

The `chrome://flags/#allow-insecure-localhost` is a convenience and security compromise:

- It's possibly a fair work-around if you'll be using an isolated testing only chrome profile.
- But it's not going to help understand and test basic TLS and X509 functionality on an app bound to localhost.

#### 3rd party CAs and localhost

Furthermore, a 3rd party CA must not issue a cert for 127.0.0.1 or localhost. As per [Let's encrypt - Certificates for localhost](https://letsencrypt.org/docs/certificates-for-localhost/)

> Let's Encrypt can't provide certificates for "localhost" because nobody uniquely owns it, and it's not rooted in a top level domain like ".com" or ".net"

## Personal certificate authority (CA)

Create an individual root CA for code signing or issuing other certs:

- `.env` has has default settings used by scripts
  - Instead of using something sed/awk to modify a base openssl config file, openssl config is built and read in from the shell environment variables.
- `CN=Personal Root CA` is the default simple distingushed name (DN)/subject applied unless env vars are set.
- Creating an `vars.env` file allows for customising the location and parts of the certificate subject (DN) such as location and organisation. For example, in vars.env, the following could be set:
  - `O=<legal entity name>`
  - `C=<2 letter country code>`
  - `ST=<State or province>`
  - `L=<location>`
- Alternatively, instead of `vars.env`, directly control the subject/DN string by setting `ROOT_CA_DN` for the root authority and `DN` for the signed certificates.
- Exporting a `CA_PASSPHRASE` env var with spaces helps avoid exposing the password in bash history (assuming `HISTCONTROL=ignorespace` set).

```bash
  export CA_PASSPHRASE='<your own CA private key passphrase>'
./create_personal_ca.sh
```

Create a cert for personal code signing where `DN` env var or `vars.env` sourced env vars apply:

- `CODESIGN_PASSPHRASE` env var is used to encrypt the private key.
- `CN="Personal Code Signing"` is the default common name if no `DN`, `CN` or `vars.env` apply.

```bash
  export CODESIGN_PASSPHRASE='<your own passphrase to use when singing code with the private key>'
./issue_code_sign_cert.sh
```

The certificate extensions of interest are:

```console
        X509v3 extensions:
            X509v3 Key Usage: 
                Digital Signature
            X509v3 Extended Key Usage: 
                Code Signing, Microsoft Individual Code Signing

```

Create a cert for localhost TLS server or client authentication where `DN` env var or `vars.env` sourced env vars apply:

- `TLS_PASSPHRASE` env var is used to encrypt the private key.
- `CN="$HOSTNAME"` is the default common name if no `DN`, `CN` or `vars.env` apply.
- X509v3 subject alternative names for the CN, localhost and localhost IP addresses are also created as required by modern browser TLS standards.

```bash
  export TLS_PASSPHRASE='<your own passphrase for the .pfx file exported>'
./issue_tls_local_cert.sh
```

The certificate subject alternative names and key usage extensions of interest (for use with localhost):

```console
        X509v3 extensions:
            X509v3 Key Usage: 
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Subject Alternative Name: 
                DNS:<HOSTNAME>, DNS:localhost, DNS:localhost.localdomain IP:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
```

For issued certificates, a PKCS#12 export file format is also supplied:

- Java and Windows crypto APIs import this format more simply (compared to separate `.pem` files).
- While openssl can export to PKCS#12 without a passphrase, the Java standard libraries and utilities don't function without passwords.

References:

- [Root CA Configuration File](https://pki-tutorial.readthedocs.io/en/latest/expert/root-ca.conf.html)
- [Create your own certificate authority (for testing)](https://coolaj86.com/articles/create-your-own-certificate-authority-for-testing/)
- [Creating a CA](https://www.phildev.net/ssl/creating_ca.html)
- [Bash script with config baked in](https://serverfault.com/questions/845766/generating-a-self-signed-cert-with-openssl-that-works-in-chrome-58/870832#870832)
- [Keystore without a password](https://blog.jdriven.com/2015/10/keystore-without-a-password/)

### Importing and trusting a personal CA

Reference:

- [How to import CA root certificates on Linux and Windows](https://thomas-leister.de/en/how-to-import-ca-root-certificate/)

#### Importing personal CA into windows OS

Running `certlm.msc` or double clicking the root CA `.der` file into "Trusted Root Certification Authorities" for the local computer if the scope is for all windows accounts including an Administrative context.

Or via and administrative powershell:

```powershell
Import-Certificate -FilePath .\personal_root_ca.cert.der -CertStoreLocation cert:\LocalMachine\Root
```

Reference:

- [Certificates](https://docs.microsoft.com/en-us/previous-versions/tn-archive/cc700805(v=technet.10))

#### Importing personal CA into browsers

Import `ca/certs/personal_root_ca.cert.pem` into browser authorities. This can differ per platform. See:

- [Root Certificate Policy](https://www.chromium.org/Home/chromium-security/root-ca-policy)
- [Linux Cert Management](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/linux_cert_management.md)
- [CA/AddRootToFirefox](https://wiki.mozilla.org/CA/AddRootToFirefox)

Chrome's authorities can be managed via `chrome://settings/certificates`.

On Linux `nss` libs and `certutil` can help import a personal CA via the CLI:

```bash
certutil -d sql:$HOME/.pki/nssdb -A -t 'CT,c,c' -n personal_root_ca -i ./ca/certs/personal_root_ca.cert.pem
certutil -d /home/a211278l/.pki/nssdb -L -n personal_root_ca
```

As per `-t trustargs` described by [NSS Tools certutil
](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/tools/NSS_Tools_certutil):

> - c    Valid CA
> - T    Trusted CA to issue client certificates (implies c)
> - C    Trusted CA to issue server certificates (SSL only)

Note the output of `certutil -d /home/a211278l/.pki/nssdb -L -n personal_root_ca` option helps confirm:

```console
    Certificate Trust Flags:
        SSL Flags:
            Valid CA
            Trusted CA
            Trusted Client CA
        Email Flags:
            Valid CA
        Object Signing Flags:
            Valid CA
```

And to validate the purpose of the cert via certutil `-u` usage check:

```bash
$ certutil -d sql:$HOME/.pki/nssdb -V -u L -n personal_root_ca
certutil: certificate is valid
```

Where the `-u L` flag checks if the CA is suitable for issuing TLS certificates.

### PowerShell digital signatures (code-signing) with a personal CA

OpenSSL code signing references:

- [Code-Signing Certificate Request Configuration File](https://pki-tutorial.readthedocs.io/en/latest/advanced/codesign.conf.html).

PowerShell code signing references:

- [How to sign Windows Powershell Scripts](https://knowledge.digicert.com/solution/SO9982.html) - via official CA.
- [How to: (Windows 10) Signing a Powershell Script with a Self-Signed Certificate](https://community.spiceworks.com/how_to/153255-windows-10-signing-a-powershell-script-with-a-self-signed-certificate) - to create own self-signed signing cert
- [How do I create a self-signed certificate for code signing on Windows?](https://stackoverflow.com/questions/84847/how-do-i-create-a-self-signed-certificate-for-code-signing-on-windows) - answer showing windows command utilities that manage certs.
- [Create Code Signing Certificate on Windows for signing PowerShell scripts](https://serverfault.com/questions/824574/create-code-signing-certificate-on-windows-for-signing-powershell-scripts) - answer showing PowerShell.
- [Using Digital Signatures with Timestamp Server](https://community.idera.com/database-tools/powershell/powertips/b/tips/posts/using-digital-signatures-with-timestamp-server).

#### Importing code singing key and cert into windows

To trust your personal code signing cert on the whole system:

```powershell
Import-Certificate -FilePath '.\Personal Code Signing.cert.der' -CertStoreLocation cert:\LocalMachine\TrustedPublisher
```

#### Digitaly signing a powershell script

For ease of use, the private key and certificate .pfx file can be imported into the personal store:

```powershell
$passphrase = Get-Credential -User 'Code signing private key' -Message 'Passphrase for private key'
Import-PfxCertificate -FilePath 'Personal Code Signing.pfx' -CertStoreLocation Cert:\CurrentUser\My -Password $passphrase.Password
# See the thumbprint
$codeCert = Get-Childitem cert:\CurrentUser\my -CodeSigning | ? { $_.Subject -imatch 'CN=Personal Code Signing' }[0]
$codeCert.Thumbprint
```

However, a secure and less convenient approach is to only load the code singing certificate and private key when needed:

```powershell
$passphrase = Get-Credential -User 'Code signing private key' -Message 'Passphrase for private key'
$codeCert = Get-PfxCertificate -FilePath '~\Desktop\Personal Code Signing.pfx' -Password $passphrase.Password
```

To recursively sign all scripts (`.ps1`) and modules (`.psm1`) in a directory:

```powershell
Get-ChildItem -Recurse -Path . -Include @('*.ps1','*.psm1') | Set-AuthenticodeSignature -Certificate $codeCert
```

### Testing TLS authentication with a personal CA

Test with openssl and curl:

```bash
  export PASSPRHASE='change me'
openssl s_server -key ./private/$HOSTNAME.key.pem -pass env:PASSPHRASE -cert ./certs/$HOSTNAME.cert.pem -accept 20443 -www &
openssl_pid=$!
openssl s_client -CAfile ./ca/certs/personal_root_ca.cert.pem -connect 127.0.0.1:20443 < /dev/null
curl https://localhost:20443 -v -o /dev/null --cacert ca/certs/personal_root_ca.cert.pem -w "# HTTP response code = %{response_code}\n"
```

Open the site in Chrome:

```console
google-chrome https://localhost:20443
```

It should open without any cert errors.

And after testing

```bash
kill $openssl_pid
unset openssl_pid
```

## Self-signed certificates (no separate CA root)

Self-signed certificates without a CA chain appears simpler, but with the limitation of not working properly for browsers that raise exceptions about self-signed certificates used with TLS connections and various extended usage attributes causing conflicts.

### Self-signed code signing cert

If all that's required is a code signing certificate, then self-signed could be a viable and minimal way to go. You can set your own passphrase via `  export PASSPHRASE='<your passphrase>'`.

```bash
./self_signed/self_signed.sh
```

Provided NSS or alternate libraries don't strictly check for key usage conflicts, the above might work well enough.

### Self-signed cert for TLS and code signing

I did attempt to use a multipurpose self signed cert. However, it was not possible to get Chrome 71 to trust it.

E.g. from the `self_signed_eg` directory:

```bash
./self_signed/self_signed.sh
```

The above cert has the right key and extended key ussage attributes set for TLS sever and client authentication as well as code signing.

This can be imported into the local NSS database used by chrome.

```bash
certutil -d sql:$HOME/.pki/nssdb -A -t 'CT,c,c' -n personal_self_signed -i $HOSTNAME.cert.pem
```

#### Testing TLS self-signed

OpenSSL tests:

```bash
  export PASSPHRASE='change me'
openssl s_server -key "$HOSTNAME.key.pem" -pass env:PASSPHRASE -cert "$HOSTNAME.cert.pem" -accept 20443 -www &
openssl_pid=$!
openssl s_client -CAfile "$HOSTNAME.cert.pem" -connect 127.0.0.1:20443 < /dev/null
```

The result I saw near the end of the output was `Verify return code: 0 (ok)`. So OpenSSL accepts the self-signed certificate as valid, but is more relaxed about key usage compared to NSS.

Curl also works: (with a somewhat benign TLS connection termination error, but session establishment succeeded):

```console
$ curl https://localhost:20443 -v -o /dev/null --cacert $HOSTNAME.cert.pem -w "# HTTP response code = %{response_code}\n"
...
* SSL connection using TLS1.2 / ECDHE_RSA_AES_128_GCM_SHA256
* 	 server certificate verification OK
...
# HTTP response code = 200
curl: (56) GnuTLS recv error (-110): The TLS connection was non-properly terminated.
```

After importing to NSS and testing via Chrome at `google-chrome https://localhost.localdomain:20443/`, the self-signed cert it's not trusted and the following error is seen in the chrome GUI:

```console
NET::ERR_CERT_INVALID
```

On the console:

```console
ERROR:cert_verify_proc_nss.cc(974)] CERT_PKIXVerifyCert for localhost failed err=-8101
```

As per [NSS and SSL Error Codes](https://www-archive.mozilla.org/projects/security/pki/nss/ref/ssl/sslerr.html):

| Constant | Value | Description |
| - | - | - |
| SEC_ERROR_INADEQUATE_CERT_TYPE | -8101 | Certificate type not approved for application. |
| SEC_ERROR_INADEQUATE_KEY_USAGE | -8102 | Certificate key usage inadequate for attempted operation. |

Futhermore, during testing, without `anyExtendedKeyUsage` set, error code `-8102` was also observed.

NSS appears to distrust the certificate for use as a TLS sever because the extend key usage extensions conflicts with the CA basic usage. Note the condensed output seems to contradict this given usages of 'Digital Signature', 'Key Encipherment' and extended usage of 'TLS Web Server Authentication Certificate' were included:

```console
$ certutil -d /home/a211278l/.pki/nssdb -L -n personal_self_signed
...
      Signed Extensions:
            Name: Certificate Subject Alt Name
            DNS name: "<$HOSTNAME>"
            DNS name: "localhost"
            DNS name: "localhost.localdomain"
            IP Address: 127.0.0.1
            IP Address: ::1

            ...

            Name: Certificate Basic Constraints
            Critical: True
            Data: Is a CA with a maximum path length of 0.

            Name: Certificate Key Usage
            Usages: Digital Signature
                    Key Encipherment
                    Certificate Signing

            Name: Extended Key Usage
                TLS Web Server Authentication Certificate
                TLS Web Client Authentication Certificate
                Code Signing Certificate
                OID.2.5.29.37.0
```

And `certutil` allows confirms the certificate is valid as an SSL CA:

```console
$ certutil -d sql:$HOME/.pki/nssdb -V -u L -n personal_self_signed
certutil: certificate is valid
```

But not 'approved' as valid for TLS server authentication:

```console
$ certutil -d sql:$HOME/.pki/nssdb -V -u V -n personal_self_signed
certutil: certificate is invalid: Certificate type not approved for application.
```

Note, the man page for certutil has a section for usage validation flags:

>       -u certusage
>           Specify a usage context to apply when validating a certificate with
>           the -V option.

And the flags used:

- `-u V`: SSL server
- `-u L`: SSL CA
- `-u A`: Any CA

Post testing cleanup:

```bash
kill $openssl_pid
certutil -d /home/a211278l/.pki/nssdb -D -n personal_self_signed
rm $HOSTNAME.*.pem
rm $HOSTNAME.*.pfx
```