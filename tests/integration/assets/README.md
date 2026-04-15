# Integration Asset Notes

This directory stores JSON templates and rules files used by the live
single-sig integration workflow.

## Files

- `le-edge-template.json`: edge template for issuing the LE credential from the
  QVI credential.
- `qvi-rules.json`: rules payload used for QVI and LE issuance in the live
  chain.
- `vrd-auth-edge-template.json`: edge template for issuing VRD Auth from the LE
  credential.
- `vrd-edge-template.json`: edge template for issuing the VRD credential in the
  live workflow.
- `vrd-auth-rules.json`: rules payload used for VRD Auth issuance.
- `vrd-rules.json`: rules payload used for VRD issuance.

## Maintenance Rules

- Edge templates are rendered into the live stack's temp directory before they
  are SAIDified. Placeholders such as `__LE_CREDENTIAL_SAID__` and
  `__QVI_CREDENTIAL_SAID__` are expected to be replaced at runtime.
- Rules files are copied or SAIDified at runtime but are otherwise treated as
  source-controlled issuance inputs.
- Keep these assets aligned with the corresponding helpers in
  `tests/integration/test_single_sig_vrd_isomer.py` and
  `tests/integration/kli_flow.py`.
- If schema or edge semantics change, update these assets together with the
  live test so the workflow remains internally coherent.
