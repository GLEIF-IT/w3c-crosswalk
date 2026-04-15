"""Contract tests for did:webs resolver URL construction and parsing."""

from __future__ import annotations

from urllib.parse import quote, unquote

from w3c_crosswalk.common import canonicalize_did_url, canonicalize_did_webs
from w3c_crosswalk.didwebs import resolution_url


def test_canonicalize_did_webs_encodes_raw_port_separator():
    """Normalize malformed local did:webs values before resolver URL encoding."""
    did = "did:webs:127.0.0.1:59649:dws:EDiRogF6HnCw35tZ_lbGxGPQr527od6D_Uc6LNr6Xi_d"

    assert canonicalize_did_webs(did) == "did:webs:127.0.0.1%3A59649:dws:EDiRogF6HnCw35tZ_lbGxGPQr527od6D_Uc6LNr6Xi_d"


def test_canonicalize_did_url_preserves_fragment_while_normalizing_did():
    """Normalize the DID component of a DID URL without rewriting its fragment."""
    did_url = "did:webs:127.0.0.1:59649:dws:EDiRogF6HnCw35tZ_lbGxGPQr527od6D_Uc6LNr6Xi_d#key-1"

    assert canonicalize_did_url(did_url) == (
        "did:webs:127.0.0.1%3A59649:dws:EDiRogF6HnCw35tZ_lbGxGPQr527od6D_Uc6LNr6Xi_d#key-1"
    )


def test_resolution_url_leaves_transport_quoting_to_hio_clienting():
    """Return the canonical DID raw so HIO applies exactly one path-encoding layer."""
    base_url = "http://127.0.0.1:59650/1.0/identifiers"
    did = "did:webs:127.0.0.1%3A59649:dws:EDiRogF6HnCw35tZ_lbGxGPQr527od6D_Uc6LNr6Xi_d"

    assert resolution_url(base_url, did) == (
        "http://127.0.0.1:59650/1.0/identifiers/"
        "did:webs:127.0.0.1%3A59649:dws:EDiRogF6HnCw35tZ_lbGxGPQr527od6D_Uc6LNr6Xi_d"
    )


def test_hio_path_quote_matches_did_webs_resolver_requote_expectation():
    """One HIO path quote gives didding.requote a once-encoded did:webs value."""
    did = "did:webs:127.0.0.1%3A59649:dws:EDiRogF6HnCw35tZ_lbGxGPQr527od6D_Uc6LNr6Xi_d"
    hio_request_path = quote(f"/1.0/identifiers/{did}")

    assert hio_request_path.endswith(
        "/did%3Awebs%3A127.0.0.1%253A59649%3Adws%3AEDiRogF6HnCw35tZ_lbGxGPQr527od6D_Uc6LNr6Xi_d"
    )
    assert unquote(hio_request_path.rsplit("/", 1)[-1]) == did
