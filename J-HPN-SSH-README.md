# Building J-HPN-SSH:

## Currently, the following is the "_standard_" build (on Fedora 33):

```
make clean; make distclean; autoreconf -vfi && LD_LIBRARY_PATH=/opt/hpnssl/lib ./configure --build=x86_64-redhat-linux-gnu --host=x86_64-redhat-linux-gnu --prefix=/opt/jhpnssh --with-default-path=/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin --with-superuser-path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin --with-privsep-path=/var/empty/sshd --without-zlib-version-check --with-ssl-engine --with-ipaddr-display --with-pie=yes --with-systemd --with-default-pkcs11-provider=yes --with-security-key-builtin=yes --with-pam --with-audit=linux --with-sandbox=seccomp_filter --with-libedit --with-4in6 --with-ldns --with-ldns CFLAGS="-I/opt/hpnssl/include" --with-ldflags="-L/opt/hpnssl/lib"
```

- `/opt/hpnssl` contains the latest stable 1.1.1 LTS OpenSSL release, built
  using `./config --prefix=/opt/hpnssl`.

  - This is due to some bugs/errors the J-HPN-SSH maintained is working to track
    down on Fedora systems. On these systems, Kerberos and TCP-Wrappers should
    not be enabled, as they are linked to the system OpenSSL library. Linking to
    multiple versions of OpenSSL in such a way is not supported. Also,
    TCP-Wrappers support has been deprecated as of RHEL 8 and Fedora 23.

  - If you see any runtime errors such as:
    `debug1: EVP_KDF_derive(ctx, key, key_len) != 1 [preauth]` or
    `ssh_dispatch_run_fatal: ... error in libcrypto [preauth]`, then you are
    likely affected by this bug, and should build a separate OpenSSL library for
    J-HPN-SSH to use, as described above.

- It is **highly recommend** to use the ldns libraries, as they provide well
  tested first-class DNSSEC support. Upstream and third-party patches for
  supporting DNSSEC without ldns have been merged, however, this configuration
  is currently not well tested; feedback here would be appreciated.

- Currently, SELinux support is known to be broken, but should be fixed soon.
