# **J-HPN-SSH** - **High Performance SSH**

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/978f333599b34df584212b8d078a053e)](https://app.codacy.com/gh/johnsonjh/j-hpn-ssh?utm_source=github.com&utm_medium=referral&utm_content=johnsonjh/j-hpn-ssh&utm_campaign=Badge_Grade_Settings)

## What is **HPN-SSH**?

**HPN-SSH** is a series of modifications to _OpenSSH_, the predominant
implementation of the _SSH_ protocol. It was originally developed to address
performance issues when using _SSH_ on high speed long distance networks (also
known as _Long Fat Networks_ or _LFN's_). By taking advantage of automatically
optimized receive buffers, **HPN-SSH** can improve performance dramatically on
these paths. Other advances include optionally disabling encryption after
authentication to transport non-sensitive bulk data, modifying the AES-CTR
cipher to use multiple CPU cores, more detailed connection logging, and peak
throughput value calculations shown in the _SCP_ progress bar.

## **J-HPN-SSH** Fork Information

**J-HPN-SSH** is an experimental development fork of **HPN-SSH**. It is not
associated in any way with the upstream project. It currently incorporates
changes from IBM and Red Hat's SSH distribtions, as well as adjustments to the
congestion control and buffering algorithms.

## **J-HPN-SSH** Future Plans

Current plans include the tuning and assembly-level optimization of existing
code, as well as the addition of new cryptographic functionality, including
post-quantum algorithms, enhanced hashing and key exchange mechanisms, and new
key systems, such as SHAKE, SHA-3, BLAKE-3, Schnorrkel/Ristretto-Sr25519,
Ristretto255/Curve25519-Dalek, X448-Goldilocks, E-5321, Kyber, SIDH, Dilithium,
SPHINCS-SHAKE256, SPHINCS+, etc.

Experiments that are successful will be made available to the upstream
**HPN-SSH** project.

## Security Information

This software may contain bugs, including critical security vulnerabilties,
despite the authors best efforts.

## Warranty

**BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY FOR THE
PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. EXCEPT WHEN OTHERWISE STATED
IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIESPROVIDE THE PROGRAM "AS IS"
WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE
PROGRAM IS WITH YOU. SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF
ALL NECESSARY SERVICING, REPAIR OR CORRECTION. IN NO EVENT UNLESS REQUIRED BY
APPLICABLE LAW OR AGREED TO IN WRITING WILL ANY COPYRIGHT HOLDER, OR ANY OTHER
PARTY WHO MAY MODIFY AND/OR REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE
LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR
CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE THE PROGRAM
(INCLUDING BUT NOT LIMITED TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR
LOSSES SUSTAINED BY YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE
WITH ANY OTHERPROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF
THE POSSIBILITY OF SUCH DAMAGES.**

## Licensing

See the [LICENSE](https://github.com/johnsonjh/hpn-ssh/blob/master/LICENCE) file
for full details.

## Operational Details

_SCP_ and the underlying _SSH-2_ protocol implementation in _OpenSSH_ is network
performance limited by statically defined internal flow control buffers. These
buffers often end up acting as a bottleneck for network throughput of _SCP_,
especially on long and high bandwith network links. Modifying the SSH code to
allow the buffers to be defined at run time eliminates this bottleneck.
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

## Performance Gap

With most high-bandwidth connections, there is a performance gap between what
_SSH_ is capable of, and what the network link has the capacity to do. This gap,
in most situations, is the direct cause of undersized receive buffers in _SSH_'s
congestion control mechanism.

## Normal _SSH_ _SCP_ vs. **HPN-SSH** _SCP_ Performance

**HPN-SSH** offers _significantly_ enhanced _SCP_ throughput performance.
Increasing the size of the _SSH_ channel receive buffers has been shown to
improve _SCP_ throughput by as much as **1,000%**.

## Possible bug with `buffer_append_space`

If you are experiencing disconnects due to a failure in `buffer_append_space`,
you should try using `-oHPNBufferSize=16384` to restrict the growth of this
buffer.

## Upstream **HPN-SSH** Future Plans

- Automatic resumption of failed transfers
- AES-NI hardware acceleration for the AES-CTR cipher
- Parallelization of the ChaCha-20 cipher
- Inline network telemetry
- Pipelined HMAC generation
- Enhanced distribution packaging

## **HPN-SSH** Original Authors

- Chris Rapier
- Michael Stevens
- Benjamin Bennett
- Mike Tasota

## Upstream **HPN-SSH** Homepage

- https://www.psc.edu/research/networking/hpn-ssh/
