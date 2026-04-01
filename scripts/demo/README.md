# Demo Scripts

The CLI-first demonstration scripts (planned)

Planned script sequence:

1. Start witnesses and the vLEI issuance spine from `qvi-software`
2. Start `did-webs-resolver`
3. Start crosswalk status service
4. Issue or load VRD Auth and VRD ACDCs
5. Derive and sign W3C VC-JWT twins
6. Verify ACDC in Sally/other Python verifier
7. Verify W3C VC-JWT and VP-JWT in the crosswalk verifier
8. Revoke the ACDC source and observe W3C revocation failure

The implementation in this initial landing provides the CLI and service seams
those scripts will wrap.

