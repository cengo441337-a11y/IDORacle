"""verified_autonomy.receipt - a portable, content-addressed verification receipt.

A receipt is a tamper-evident record that a specific artifact passed a specific
spine at a specific time. It is content-addressed (sha256 of the exact bytes that
were verified), carries the per-check verdicts, and can be signed by a pluggable
signer. "Prove the agent was gated" becomes a cryptographic artifact, not a claim.

The claims here are deliberately envelope-agnostic. The same claims can be
wrapped in an in-toto attestation, a C2PA manifest, or a W3C Verifiable
Credential for ecosystem interop - those are adapters around this core, not a
different record. Stdlib only; the reference signer is HMAC-SHA256, with
ed25519 / Sigstore as the documented production path via the same `Signer` hook.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass, field
from typing import Callable, Dict, List, Optional

RECEIPT_SCHEMA = "verified-autonomy/receipt/v1"
IN_TOTO_PREDICATE_TYPE = "https://verified-autonomy.dev/receipt/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"

# A Signer maps the canonical claim bytes to a signature object.
Signer = Callable[[bytes], Dict[str, str]]
# A Verifier checks canonical claim bytes against a signature object.
Verifier = Callable[[bytes, Dict[str, str]], bool]


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass
class Receipt:
    schema: str
    artifact_sha256: str
    artifact_len: int
    overall: str                       # pass | hold | fail
    lane: str                          # normal | high-stakes
    checks: List[Dict[str, str]]       # [{name, verdict, detail}]
    spine_id: str
    created_at: str                    # ISO-8601, injected by the caller
    signature: Optional[Dict[str, str]] = None
    meta: Dict[str, str] = field(default_factory=dict)
    corpus_hash: Optional[str] = None       # hash of the calibration corpus, if known
    fn_bound: Optional[float] = None        # one-sided FN upper bound for this spine
    capability_tier: Optional[str] = None   # attested capability tier (see `va doctor`)
    # v2 assurance: the machine-negotiable trust payload. Per-class FN bounds, the
    # capability tier, and - the genuinely novel part - a signed NEGATIVE capability
    # envelope stating, per defect class, what this check provably CANNOT catch.
    assurance: Optional[Dict] = None

    def claims(self) -> dict:
        """Everything that is signed: the receipt minus its own signature."""
        d = asdict(self)
        d.pop("signature", None)
        return d

    def canonical(self) -> str:
        """Deterministic JSON of the claims - the exact bytes that get signed."""
        return json.dumps(self.claims(), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(asdict(self), sort_keys=True, indent=indent, ensure_ascii=False)


def build_receipt(text: str, report, *, lane: str, created_at: str,
                  spine_id: str = "default", meta: Optional[Dict[str, str]] = None,
                  corpus_hash: Optional[str] = None, fn_bound: Optional[float] = None,
                  capability_tier: Optional[str] = None,
                  assurance: Optional[Dict] = None) -> Receipt:
    """Build a receipt from the verified text and a SpineReport.

    `created_at` is injected (no hidden clock) so the library stays deterministic
    and testable; the CLI passes a real UTC timestamp. The optional corpus_hash /
    fn_bound / capability_tier carry the calibration + capability evidence that
    make a receipt audit-grade rather than a bare pass/fail.
    """
    return Receipt(
        schema=RECEIPT_SCHEMA,
        artifact_sha256=sha256_hex(text),
        artifact_len=len(text),
        overall=report.overall.value,
        lane=lane,
        checks=[{"name": c.name, "verdict": c.verdict.value, "detail": c.detail}
                for c in report.results],
        spine_id=spine_id,
        created_at=created_at,
        meta=meta or {},
        corpus_hash=corpus_hash,
        fn_bound=fn_bound,
        capability_tier=capability_tier,
        assurance=assurance,
    )


def to_in_toto(receipt: Receipt, subject_name: str = "deliverable") -> dict:
    """Wrap the receipt claims as an in-toto v1 Statement so it rides existing
    supply-chain rails (Sigstore / SLSA tooling) as a custom predicate."""
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": subject_name,
                     "digest": {"sha256": receipt.artifact_sha256}}],
        "predicateType": IN_TOTO_PREDICATE_TYPE,
        "predicate": receipt.claims(),
    }


def to_dsse(receipt: Receipt, subject_name: str = "deliverable") -> dict:
    """Wrap as an in-toto Statement, PRESERVING the signature in a DSSE-style
    envelope when one is present (the in-toto predicate has no signature slot, so
    a bare statement would silently drop it). Unsigned receipts return the bare
    Statement. `receipt_from_json` transparently restores the signature."""
    stmt = to_in_toto(receipt, subject_name)
    if receipt.signature:
        return {"payloadType": DSSE_PAYLOAD_TYPE, "statement": stmt,
                "signatures": [receipt.signature]}
    return stmt


def sign_receipt(receipt: Receipt, signer: Signer) -> Receipt:
    receipt.signature = signer(receipt.canonical().encode("utf-8"))
    return receipt


def verify_receipt(receipt: Receipt, text: str, *,
                   verifier: Optional[Verifier] = None) -> Dict[str, Optional[bool]]:
    """Check that (1) the artifact hash still matches `text`, and (2) the
    signature verifies (only if a `verifier` is supplied).

    Returns {artifact_ok, signature_ok, ok}. `signature_ok` is None when no
    verifier was given (signature not checked). `ok` is False if the artifact was
    tampered with, or if a signature was checked and failed.
    """
    artifact_ok = (sha256_hex(text) == receipt.artifact_sha256
                   and len(text) == receipt.artifact_len)
    signature_ok: Optional[bool] = None
    if verifier is not None:
        signature_ok = bool(receipt.signature) and verifier(
            receipt.canonical().encode("utf-8"), receipt.signature)
    ok = artifact_ok and (signature_ok is not False)
    return {"artifact_ok": artifact_ok, "signature_ok": signature_ok, "ok": ok}


def receipt_from_json(blob: str) -> Receipt:
    """Parse a bare receipt, an in-toto Statement, or a DSSE envelope wrapping one.
    A DSSE envelope's signature is restored onto the receipt; a bare in-toto
    Statement has no signature slot, so signature is None (unauthenticated)."""
    obj = json.loads(blob)
    if isinstance(obj, dict) and obj.get("payloadType") == DSSE_PAYLOAD_TYPE and "statement" in obj:
        sig = (obj.get("signatures") or [None])[0]
        claims = dict((obj["statement"] or {}).get("predicate") or {})
        claims["signature"] = sig
        return Receipt(**claims)
    if isinstance(obj, dict) and obj.get("predicateType") == IN_TOTO_PREDICATE_TYPE:
        obj = dict(obj.get("predicate") or {})  # the inner claims (no signature)
    return Receipt(**obj)


# --- Reference HMAC signer/verifier (zero-dep). Production: ed25519 / Sigstore.

def hmac_signer(secret: str, key_id: str = "hmac") -> Signer:
    def _sign(data: bytes) -> Dict[str, str]:
        mac = hmac.new(secret.encode("utf-8"), data, hashlib.sha256).hexdigest()
        return {"alg": "HMAC-SHA256", "key_id": key_id, "sig": mac}
    return _sign


def hmac_verifier(secret: str) -> Verifier:
    def _verify(data: bytes, sig: Dict[str, str]) -> bool:
        if not sig or sig.get("alg") != "HMAC-SHA256":
            return False
        expected = hmac.new(secret.encode("utf-8"), data, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig.get("sig", ""))
    return _verify


# --- Production signer: ed25519 (cross-org trust). Needs `cryptography`
# (pip install "verified-autonomy[crypto]"). Same Signer/Verifier hooks as HMAC.

def _require_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: F401
            Ed25519PrivateKey, Ed25519PublicKey)
    except Exception as exc:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(
            "ed25519 signing needs the 'crypto' extra: pip install "
            "'verified-autonomy[crypto]'") from exc
    from cryptography.hazmat.primitives.asymmetric import ed25519
    return ed25519


def ed25519_signer(private_key, key_id: str = "ed25519") -> Signer:
    """`private_key` is an Ed25519PrivateKey (or 32 raw seed bytes)."""
    ed25519 = _require_crypto()
    if isinstance(private_key, (bytes, bytearray)):
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(private_key))

    def _sign(data: bytes) -> Dict[str, str]:
        return {"alg": "ed25519", "key_id": key_id, "sig": private_key.sign(data).hex()}
    return _sign


def ed25519_verifier(public_key) -> Verifier:
    """`public_key` is an Ed25519PublicKey (or 32 raw bytes)."""
    ed25519 = _require_crypto()
    if isinstance(public_key, (bytes, bytearray)):
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes(public_key))

    def _verify(data: bytes, sig: Dict[str, str]) -> bool:
        if not sig or sig.get("alg") != "ed25519":
            return False
        try:
            from cryptography.exceptions import InvalidSignature
            public_key.verify(bytes.fromhex(sig.get("sig", "")), data)
            return True
        except (InvalidSignature, ValueError):
            return False
    return _verify
