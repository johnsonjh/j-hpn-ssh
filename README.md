# **J-HPN-SSH**

## **High-Performance SSH**

[![License](https://img.shields.io/badge/License-BSD-blue.svg)](https://github.com/johnsonjh/j-hpn-ssh/blob/master/LICENSE)
[![LocCount](https://img.shields.io/tokei/lines/github/johnsonjh/j-hpn-ssh.svg)](https://github.com/XAMPPRocky/tokei)
[![GitHubCodeSize](https://img.shields.io/github/languages/code-size/johnsonjh/j-hpn-ssh.svg)](https://github.com/johnsonjh/j-hpn-ssh)
[![TickgitTODOs](https://img.shields.io/endpoint?url=https://api.tickgit.com/badge?repo=github.com/johnsonjh/j-hpn-ssh)](https://www.tickgit.com/browse?repo=github.com/johnsonjh/j-hpn-ssh)

[![CodebeatBadge](https://codebeat.co/badges/3f8c5f7e-c56d-4f8c-8c86-a40f35aeb065)](https://codebeat.co/projects/github-com-johnsonjh-j-hpn-ssh-master)
[![CodacyBadge](https://app.codacy.com/project/badge/Grade/c5452a711cfa436dbc1f1edb49c8ebd6)](https://www.codacy.com/gh/johnsonjh/j-hpn-ssh/dashboard?utm_source=github.com&utm_medium=referral&utm_content=johnsonjh/j-hpn-ssh&utm_campaign=Badge_Grade)
[![DeepSourceActive](https://deepsource.io/gh/johnsonjh/j-hpn-ssh.svg/?label=active+issues)](https://deepsource.io/gh/johnsonjh/j-hpn-ssh/?ref=repository-badge)
[![DeepSourceResolved](https://deepsource.io/gh/johnsonjh/j-hpn-ssh.svg/?label=resolved+issues)](https://deepsource.io/gh/johnsonjh/j-hpn-ssh/?ref=repository-badge)

## What is **HPN-SSH**?

**HPN-SSH** is a series of modifications to _OpenSSH_, the predominant
implementation of the _SSH_ protocol. It was originally developed to address
performance issues when using _SSH_ on high speed long distance networks (also
known as _Long Fat Networks_ or _LFN's_).

By taking advantage of automatically optimized receive buffers, **HPN-SSH** can
improve performance dramatically on these paths. Other advances include
optionally disabling encryption after authentication to transport non-sensitive
bulk data, modifying the AES-CTR cipher to use multiple CPU cores, more detailed
connection logging, and peak throughput value calculations shown in the _SCP_
progress bar.

## What is **J-HPN-SSH**?

**J-HPN-SSH** is an experimental development fork of **HPN-SSH**. It is not
associated in any way with the upstream project. It currently incorporates
select changes from the IBM, Red Hat, and Debian SSH distributions, various
other patches to keep up to date with upstream _OpenSSH-portable_, and various
adjustments to **HPN-SSH**'s buffer sizing and congestion control.

## **J-HPN-SSH** future plans

Besides staying up-to-date with _OpenSSH-portable_, currently, plans include
additional tuning, including assembly-level optimization of existing code, as
well as the addition of new cryptographic functionality, likely to include new
post-quantum algorithms, enhanced hashing and key exchange mechanisms, and new
key systems, such as SHAKE, SHA-3, BLAKE-3, Schnorrkel/Ristretto-Sr25519,
Intermac, Ristretto255/Curve25519-Dalek, X448-Goldilocks, E-5321, Kyber, SIDH,
Dilithium, SPHINCS-SHAKE256, SPHINCS+, [CSIDH](https://csidh.isogeny.org/),
etc.

Experiments that are successful will be made available to the upstream
**HPN-SSH** project. No GPL or similarly licensed code will be incorporated, and
all newly added code will be licensed under the same terms and conditions of the
current _OpenSSH-portable_ and **HPN-SSH** distributions.

## Security information

This software **may** contain bugs, including **critical security
vulnerabilities**, despite the author's best efforts.

## Warranty (or lack thereof)

**BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY FOR THE
PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED
IN WRITING, THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS
IS", WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT
NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE.**

**_THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH
YOU._**

**SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY
SERVICING, REPAIR, OR CORRECTION. IN NO EVENT, UNLESS REQUIRED BY APPLICABLE LAW,
OR AGREED TO IN WRITING, WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY
MODIFY AND/OR REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR
DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
ARISING OUT OF THE USE, OR INABILITY TO USE, THE PROGRAM, INCLUDING BUT NOT
LIMITED TO, LOSS OF DATA, OR DATA BEING RENDERED INACCURATE, OR LOSSES SUSTAINED BY
YOU OR THIRD PARTIES, OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
PROGRAMS, EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
POSSIBILITY OF SUCH DAMAGES.**

## License

See the [LICENSE](https://github.com/johnsonjh/hpn-ssh/blob/master/LICENCE) file
for full details.

## Operational Details

_SCP_ and the underlying _SSH-2_ protocol implementation in _OpenSSH_ is network
performance limited by statically defined internal flow control buffers. These
buffers often end up acting as a bottleneck for network throughput of _SCP_,
especially on long and high bandwidth network links.

Modifications to the SSH code to allow these buffers to be defined at run-time
eliminate the bottleneck.

**HPN-SSH** is fully interoperable with other SSH servers and clients. In
addition, **HPN-SSH** clients will be able to download faster, even from non
**HPN-SSH** servers, and **HPN-SSH** servers will be able to receive uploads
faster, even from non **HPN-SSH** clients, as long as the host receiving the
data has a properly tuned TCP/IP stack.

The amount of improvement any specific user will see is dependent on a number of
factors. Transfer rates cannot exceed the capacity of the network, nor the
throughput of I/O subsystems, including the disk and memory speed. The
improvement will also be highly influenced by the capacity of the processor to
handle encryption (and decryption).

## Performance gap

With most high-bandwidth connections, there is a performance gap between what
_SSH_ is capable of, and what the network link has the capacity to do. This gap,
in most situations, is the direct cause of undersized receive buffers in _SSH_'s
congestion control mechanism.

## Normal _SSH_ _SCP_ vs. **HPN-SSH** _SCP_ performance

**HPN-SSH** offers _significantly_ enhanced _SCP_ throughput performance.
Increasing the size of the _SSH_ channel receive buffers has been shown to
improve _SCP_ throughput by as much as **1,000%**.

## Possible bug with `buffer_append_space`

If you are experiencing disconnects due to a failure in `buffer_append_space`,
you should try using `-oHPNBufferSize=16384` to restrict the growth of this
buffer.

## **J-HPN-SSH**-specific notes

### This is the "_standard_" configuration, primarily tested on _Fedora 33_:

```shell
make clean; make distclean; export LD_LIBRARY_PATH=/opt/hpnssl/lib && autoreconf -vfi
./configure --build=x86_64-redhat-linux-gnu --host=x86_64-redhat-linux-gnu \
--prefix=/opt/jhpnssh --with-default-pkcs11-provider=yes --with-ldns \
--with-default-path=/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin \
--with-superuser-path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin \
--with-privsep-path=/var/empty/sshd --without-zlib-version-check --with-ssl-engine \
--with-ipaddr-display --with-pie=yes --with-systemd --with-security-key-builtin=yes \
--with-pam --with-audit=linux --with-sandbox=seccomp_filter --with-libedit --with-4in6 \
--with-ldns CFLAGS="-I/opt/hpnssl/include" --with-ldflags="-L/opt/hpnssl/lib" && \
make -j "${CPUS:-1}" && sudo make install
```

- `/opt/hpnssl` contains the _latest stable_ 1.1.1 LTS _OpenSSL_ release.

  - Build with defaults:
    `./config --prefix=/opt/hpnssl && make -j "${CPUS:-1}" && sudo make install`.

    - This is due to some bugs/errors the **J-HPN-SSH** maintainer is working to
      track down on Red Hat/Fedora systems. Also, on these systems, _Kerberos 5_
      and _TCP-Wrappers_ should not be enabled, as they are almost always linked
      to the system _OpenSSL_ library. Linking to multiple versions of _OpenSSL_
      this way is **not** a supported configuration.

      - Compilation with OpenSSL 3-alpha is known to work (and periodically tested),
        however, care must be taken to avoid OpenSSL version conflicts when linking.

  - _TCP-Wrappers_ support has been deprecated as of _RHEL 8_ and _Fedora 23_;
    the `tcp_wrappers-devel` package that provides the necessary headers is no
    longer made available; the standard Red Hat _SSH_ does not include any
    support for _TCP-Wrappers_. If you want to enable _TCP-Wrappers_ on these
    systems, you will need to compile and install _TCP-Wrappers_ from source
    code, preferably, the most recently released Red Hat SRPM's, which were
    distributed with _RHEL 7_.

    - If you see any runtime errors such as
      `debug1: EVP_KDF_derive(ctx, key, key_len) != 1 [preauth]` or
      `ssh_dispatch_run_fatal: ... error in libcrypto [preauth]`, then you are
      likely affected by this bug, and should build a separate OpenSSL library
      for **J-HPN-SSH** to use, as described above.

- It is **highly recommend** to use the _ldns_ libraries, as they provide well
  tested, first-class _DNSSEC_ support. Upstream and third-party patches for
  supporting _DNSSEC_ without _ldns_ have been merged, however, this
  configuration is currently not well tested; feedback here would be
  appreciated.

- **_Currently, SELinux support is known to be broken, but should be fixed
  soon._**

## Upstream **HPN-SSH** Future Plans

- Automatic resumption of failed transfers
- AES-NI hardware acceleration for the AES-CTR cipher
- Parallelization of the ChaCha-20 cipher
- In-line network telemetry
- Pipelined HMAC generation
- Enhanced distribution packaging

## **HPN-SSH** Original Authors

- Chris Rapier
- Michael Stevens
- Benjamin Bennett
- Mike Tasota

## **HPN-SSH** Upstream Homepage

- <https://www.psc.edu/research/networking/hpn-ssh/>
