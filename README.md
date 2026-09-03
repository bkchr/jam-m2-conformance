# jam-m2-conformance

Conformance harness for JAM prize Milestone 2 ("AUTHORER": fully conformant, produces blocks,
including networking and off-chain duties).

The harness runs a node under test as one of six tiny-spec validators, emulates the other five over
JAMNP-S with an independent protocol implementation, and validates every block and off-chain
artefact the node produces against the `polkajam-fuzz` reference engine.

Current state: design only. See [DESIGN.md](DESIGN.md).

References:
- JAM prize: https://jam.web3.foundation/
- JAMNP-S spec: https://github.com/zdave-parity/jam-np (`simple.md`)
- Graypaper: https://graypaper.com/
- M1 conformance (fuzz-proto, reports): https://github.com/davxy/jam-conformance
