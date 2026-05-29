"""
Post-quantum authentication utilities.

The project defaults to ML-DSA-65 (NIST FIPS 204) when pqcrypto is installed
and keeps the older browser-friendly WOTS-style signature bundle as a legacy
fallback for classroom compatibility.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
from typing import Dict, List, Optional, Tuple


# ============================================================================
# Optional Post-Quantum Library Detection
# ============================================================================

OQS_AVAILABLE = False
PQCRYPTO_ML_DSA_AVAILABLE = False
PQCRYPTO_SPHINCS_AVAILABLE = False
SPHINCS_AVAILABLE = False
XMSS_AVAILABLE = False

ML_DSA_ALGORITHM = "ML-DSA-65"
SPHINCS_ALGORITHM = "SPHINCS+-SHA2-256f"

try:
    import oqs  # type: ignore

    OQS_AVAILABLE = True
    print("[INFO] liboqs detected for ML-DSA signatures")
except Exception:
    oqs = None  # type: ignore

try:
    from pqcrypto.sign import ml_dsa_65  # type: ignore
    from pqcrypto.sign import sphincs_sha2_256f_simple  # type: ignore

    PQCRYPTO_ML_DSA_AVAILABLE = True
    PQCRYPTO_SPHINCS_AVAILABLE = True
    print("[INFO] pqcrypto detected for ML-DSA-65 and SPHINCS+-SHA2-256f signatures")
except ImportError:
    ml_dsa_65 = None  # type: ignore
    sphincs_sha2_256f_simple = None  # type: ignore

try:
    import sphincsplus  # type: ignore

    SPHINCS_AVAILABLE = True
    print("[INFO] sphincsplus detected for SPHINCS+ signatures")
except ImportError:
    sphincsplus = None  # type: ignore

try:
    from xmss import XMSS  # type: ignore

    XMSS_AVAILABLE = True
    print("[INFO] xmss-py detected for XMSS signatures")
except ImportError:
    XMSS = None  # type: ignore


# ============================================================================
# Encoding Helpers
# ============================================================================

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    if not isinstance(data, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", data):
        raise ValueError("value is not valid base64url")
    padding = "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(data + padding)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("value is not valid base64url") from exc


def _loads_json(value: str) -> Dict:
    try:
        loaded = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("value is not valid JSON") from exc

    if not isinstance(loaded, dict):
        raise ValueError("value must be a JSON object")
    return loaded


def _dumps_json(value: Dict) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


# ============================================================================
# WOTS-Style Hash Signature Fallback
# ============================================================================

WOTS_ALGORITHM = "WOTS-SHA256"
WOTS_PUBLIC_TYPE = "PQC-AUTH-PUBLIC"
WOTS_PRIVATE_TYPE = "PQC-AUTH-PRIVATE"
WOTS_SIGNATURE_TYPE = "PQC-AUTH-SIGNATURE"
WOTS_W = 16
WOTS_CHAIN_STEPS = WOTS_W - 1
WOTS_SECRET_SIZE = 32
WOTS_LEN1 = 64  # SHA-256 digest as 64 base-16 digits.
WOTS_LEN2 = 3   # Checksum max is 64 * 15 = 960, which fits in 3 nibbles.
WOTS_LEN = WOTS_LEN1 + WOTS_LEN2
DEFAULT_WOTS_SLOTS = 16
MAX_WOTS_SLOTS = 256


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _chain(value: bytes, steps: int) -> bytes:
    node = value
    for _ in range(steps):
        node = _sha256(node)
    return node


def _message_digits(message: str) -> List[int]:
    digest = _sha256(message.encode("utf-8"))
    digits: List[int] = []

    for byte in digest:
        digits.append(byte >> 4)
        digits.append(byte & 0x0F)

    checksum = sum(WOTS_CHAIN_STEPS - digit for digit in digits)
    checksum_digits = [
        (checksum >> 8) & 0x0F,
        (checksum >> 4) & 0x0F,
        checksum & 0x0F,
    ]

    return digits + checksum_digits


def _expected_wots_blob_size(slots: int) -> int:
    return slots * WOTS_LEN * WOTS_SECRET_SIZE


def _parse_wots_key(value: str, expected_type: str) -> Dict:
    payload = _loads_json(value)

    if payload.get("type") != expected_type:
        raise ValueError(f"expected {expected_type} key")
    if payload.get("algorithm") != WOTS_ALGORITHM:
        raise ValueError("unsupported WOTS algorithm")

    try:
        slots = int(payload.get("slots", 0))
    except (TypeError, ValueError) as exc:
        raise ValueError("signature slot count must be an integer") from exc
    if slots <= 0 or slots > MAX_WOTS_SLOTS:
        raise ValueError(f"key must contain between 1 and {MAX_WOTS_SLOTS} signature slots")

    key_material = _b64url_decode(str(payload.get("key", "")))
    if len(key_material) != _expected_wots_blob_size(slots):
        raise ValueError("key material length does not match slot count")

    return {
        "type": payload["type"],
        "algorithm": WOTS_ALGORITHM,
        "slots": slots,
        "key_material": key_material,
    }


def _parse_wots_signature(signature: str) -> Dict:
    payload = _loads_json(signature)

    if payload.get("type") != WOTS_SIGNATURE_TYPE:
        raise ValueError("expected WOTS signature")
    if payload.get("algorithm") != WOTS_ALGORITHM:
        raise ValueError("unsupported signature algorithm")

    try:
        slot = int(payload.get("slot", -1))
    except (TypeError, ValueError) as exc:
        raise ValueError("signature slot must be an integer") from exc
    signature_material = _b64url_decode(str(payload.get("signature", "")))

    if len(signature_material) != WOTS_LEN * WOTS_SECRET_SIZE:
        raise ValueError("signature material length is invalid")

    return {
        "algorithm": WOTS_ALGORITHM,
        "slot": slot,
        "signature_material": signature_material,
    }


def _generate_wots_keypair(slots: int = DEFAULT_WOTS_SLOTS) -> Tuple[str, str]:
    if slots <= 0 or slots > MAX_WOTS_SLOTS:
        raise ValueError(f"slots must be between 1 and {MAX_WOTS_SLOTS}")

    private_material = secrets.token_bytes(_expected_wots_blob_size(slots))
    public_parts = bytearray(len(private_material))

    for offset in range(0, len(private_material), WOTS_SECRET_SIZE):
        secret = private_material[offset: offset + WOTS_SECRET_SIZE]
        public_parts[offset: offset + WOTS_SECRET_SIZE] = _chain(secret, WOTS_CHAIN_STEPS)

    public_key = _dumps_json({
        "type": WOTS_PUBLIC_TYPE,
        "algorithm": WOTS_ALGORITHM,
        "slots": slots,
        "key": _b64url_encode(bytes(public_parts)),
    })
    private_key = _dumps_json({
        "type": WOTS_PRIVATE_TYPE,
        "algorithm": WOTS_ALGORITHM,
        "slots": slots,
        "key": _b64url_encode(private_material),
    })

    return public_key, private_key


def _sign_wots(message: str, private_key: str, key_index: int) -> str:
    parsed_key = _parse_wots_key(private_key, WOTS_PRIVATE_TYPE)
    slots = parsed_key["slots"]

    if key_index < 0 or key_index >= slots:
        raise ValueError("signature key index is outside the private key bundle")

    digits = _message_digits(message)
    private_material = parsed_key["key_material"]
    slot_offset = key_index * WOTS_LEN * WOTS_SECRET_SIZE
    signature_parts = bytearray(WOTS_LEN * WOTS_SECRET_SIZE)

    for idx, digit in enumerate(digits):
        offset = slot_offset + (idx * WOTS_SECRET_SIZE)
        secret = private_material[offset: offset + WOTS_SECRET_SIZE]
        signature_parts[idx * WOTS_SECRET_SIZE: (idx + 1) * WOTS_SECRET_SIZE] = _chain(secret, digit)

    return _dumps_json({
        "type": WOTS_SIGNATURE_TYPE,
        "algorithm": WOTS_ALGORITHM,
        "slot": key_index,
        "signature": _b64url_encode(bytes(signature_parts)),
    })


def _verify_wots(
    message: str,
    signature: str,
    public_key: str,
    expected_key_index: Optional[int] = None,
) -> bool:
    try:
        parsed_key = _parse_wots_key(public_key, WOTS_PUBLIC_TYPE)
        parsed_signature = _parse_wots_signature(signature)
    except ValueError:
        return False

    slot = parsed_signature["slot"]
    if expected_key_index is not None and slot != expected_key_index:
        return False
    if slot < 0 or slot >= parsed_key["slots"]:
        return False

    digits = _message_digits(message)
    public_material = parsed_key["key_material"]
    signature_material = parsed_signature["signature_material"]
    slot_offset = slot * WOTS_LEN * WOTS_SECRET_SIZE

    for idx, digit in enumerate(digits):
        sig_offset = idx * WOTS_SECRET_SIZE
        public_offset = slot_offset + sig_offset

        signature_piece = signature_material[sig_offset: sig_offset + WOTS_SECRET_SIZE]
        expected_public_piece = public_material[public_offset: public_offset + WOTS_SECRET_SIZE]
        verified_piece = _chain(signature_piece, WOTS_CHAIN_STEPS - digit)

        if not secrets.compare_digest(verified_piece, expected_public_piece):
            return False

    return True


# ============================================================================
# Main Public API
# ============================================================================

class QuantumSafeSignature:
    """
    Signature API used by both the Flask app and helper scripts.

    - Default flow: ML-DSA-65 key bundles generated by the browser and verified
      by pqcrypto/liboqs on the backend.
    - Legacy flow: WOTS-SHA256 key bundles for older demo keys.
    """

    SIGNATURE_ALGORITHM = ML_DSA_ALGORITHM if PQCRYPTO_ML_DSA_AVAILABLE or OQS_AVAILABLE else WOTS_ALGORITHM
    NONCE_LENGTH = 32
    _backend_algorithm: Optional[str] = None

    @classmethod
    def _init_backend(cls) -> None:
        if cls._backend_algorithm is not None:
            return

        if PQCRYPTO_ML_DSA_AVAILABLE or OQS_AVAILABLE:
            cls._backend_algorithm = ML_DSA_ALGORITHM
        elif PQCRYPTO_SPHINCS_AVAILABLE or SPHINCS_AVAILABLE:
            cls._backend_algorithm = SPHINCS_ALGORITHM
        elif XMSS_AVAILABLE:
            cls._backend_algorithm = "XMSS-SHA2_10_256"
        else:
            cls._backend_algorithm = WOTS_ALGORITHM

    @classmethod
    def get_backend(cls) -> str:
        cls._init_backend()
        return cls._backend_algorithm or WOTS_ALGORITHM

    @classmethod
    def get_supported_algorithms(cls) -> List[Dict[str, object]]:
        algorithms: List[Dict[str, object]] = [
            {
                "name": ML_DSA_ALGORITHM,
                "type": "lattice-based NIST FIPS 204 signature",
                "available": PQCRYPTO_ML_DSA_AVAILABLE or OQS_AVAILABLE,
                "browser_supported": True,
                "default": QuantumSafeSignature.SIGNATURE_ALGORITHM == ML_DSA_ALGORITHM,
            },
            {
                "name": WOTS_ALGORITHM,
                "type": "legacy hash-based one-time signature demo bundle",
                "available": True,
                "browser_supported": True,
                "default_slots": DEFAULT_WOTS_SLOTS,
            }
        ]

        algorithms.extend([
            {
                "name": SPHINCS_ALGORITHM,
                "type": "stateless hash-based signature",
                "available": PQCRYPTO_SPHINCS_AVAILABLE or SPHINCS_AVAILABLE,
                "browser_supported": False,
            },
            {
                "name": "XMSS-SHA2_10_256",
                "type": "stateful hash-based signature",
                "available": XMSS_AVAILABLE,
                "browser_supported": False,
            },
        ])

        return algorithms

    @staticmethod
    def generate_keypair(slots: int = DEFAULT_WOTS_SLOTS) -> Tuple[str, str]:
        """
        Generate a key pair.

        ML-DSA-65 is preferred when pqcrypto/liboqs is installed. WOTS-SHA256
        remains available only as a browser-compatible legacy fallback.
        """
        if PQCRYPTO_ML_DSA_AVAILABLE:
            public_key, private_key = ml_dsa_65.generate_keypair()  # type: ignore[union-attr]
            return (
                _dumps_json({
                    "type": WOTS_PUBLIC_TYPE,
                    "algorithm": ML_DSA_ALGORITHM,
                    "key": _b64url_encode(public_key),
                }),
                _dumps_json({
                    "type": WOTS_PRIVATE_TYPE,
                    "algorithm": ML_DSA_ALGORITHM,
                    "key": _b64url_encode(private_key),
                }),
            )

        return _generate_wots_keypair(slots)

    @staticmethod
    def sign_message(message: str, private_key: str, key_index: int = 0) -> str:
        algorithm = QuantumSafeSignature.get_private_key_algorithm(private_key)

        if algorithm == WOTS_ALGORITHM:
            return _sign_wots(message, private_key, key_index)

        return QuantumSafeSignature._sign_optional_pqc(message, private_key, algorithm)

    @staticmethod
    def verify_signature(
        message: str,
        signature: str,
        public_key: str,
        expected_key_index: Optional[int] = None,
    ) -> bool:
        algorithm = QuantumSafeSignature.get_public_key_algorithm(public_key)

        if algorithm == WOTS_ALGORITHM:
            return _verify_wots(message, signature, public_key, expected_key_index)

        return QuantumSafeSignature._verify_optional_pqc(message, signature, public_key, algorithm)

    @staticmethod
    def _sign_optional_pqc(message: str, private_key: str, algorithm: str) -> str:
        payload = _loads_json(private_key)
        secret_key = _b64url_decode(str(payload.get("key", "")))

        try:
            if algorithm == ML_DSA_ALGORITHM and PQCRYPTO_ML_DSA_AVAILABLE:
                signature = ml_dsa_65.sign(secret_key, message.encode("utf-8"))  # type: ignore[union-attr]
            elif algorithm == ML_DSA_ALGORITHM and OQS_AVAILABLE:
                signer = oqs.Signature("ML-DSA-65", secret_key)  # type: ignore[operator]
                signature = signer.sign(message.encode("utf-8"))
            elif algorithm == SPHINCS_ALGORITHM and PQCRYPTO_SPHINCS_AVAILABLE:
                signature = sphincs_sha2_256f_simple.sign(secret_key, message.encode("utf-8"))  # type: ignore[union-attr]
            elif algorithm == SPHINCS_ALGORITHM and SPHINCS_AVAILABLE:
                signature = sphincsplus.sign(message.encode("utf-8"), secret_key)  # type: ignore[union-attr]
            elif algorithm == "XMSS-SHA2_10_256" and XMSS_AVAILABLE:
                xmss_obj = XMSS.deserialize(secret_key)  # type: ignore[union-attr]
                signature = xmss_obj.sign(message.encode("utf-8"))
            else:
                raise ValueError(f"algorithm {algorithm} is not available")
        except Exception as exc:
            raise ValueError(f"failed to sign with {algorithm}: {exc}") from exc

        return _dumps_json({
            "type": WOTS_SIGNATURE_TYPE,
            "algorithm": algorithm,
            "signature": _b64url_encode(signature),
        })

    @staticmethod
    def _verify_optional_pqc(message: str, signature: str, public_key: str, algorithm: str) -> bool:
        try:
            public_payload = _loads_json(public_key)
            signature_payload = _loads_json(signature)
            public_key_bytes = _b64url_decode(str(public_payload.get("key", "")))
            signature_bytes = _b64url_decode(str(signature_payload.get("signature", "")))

            if signature_payload.get("algorithm") != algorithm:
                return False

            if algorithm == ML_DSA_ALGORITHM and PQCRYPTO_ML_DSA_AVAILABLE:
                return bool(ml_dsa_65.verify(  # type: ignore[union-attr]
                    public_key_bytes,
                    message.encode("utf-8"),
                    signature_bytes,
                ))
            if algorithm == ML_DSA_ALGORITHM and OQS_AVAILABLE:
                verifier = oqs.Signature("ML-DSA-65")  # type: ignore[operator]
                result = verifier.verify(message.encode("utf-8"), signature_bytes, public_key_bytes)
                return bool(result) if result is not None else True
            if algorithm == SPHINCS_ALGORITHM and PQCRYPTO_SPHINCS_AVAILABLE:
                return bool(sphincs_sha2_256f_simple.verify(  # type: ignore[union-attr]
                    public_key_bytes,
                    message.encode("utf-8"),
                    signature_bytes,
                ))
            if algorithm == SPHINCS_ALGORITHM and SPHINCS_AVAILABLE:
                result = sphincsplus.verify(message.encode("utf-8"), signature_bytes, public_key_bytes)  # type: ignore[union-attr]
                return bool(result) if result is not None else True
            if algorithm == "XMSS-SHA2_10_256" and XMSS_AVAILABLE:
                result = XMSS.verify(message.encode("utf-8"), signature_bytes, public_key_bytes)  # type: ignore[union-attr]
                return bool(result) if result is not None else True
        except Exception:
            return False

        return False

    @staticmethod
    def get_public_key_algorithm(public_key: str) -> str:
        payload = _loads_json(public_key)
        algorithm = payload.get("algorithm")
        if not isinstance(algorithm, str) or not algorithm:
            raise ValueError("public key is missing an algorithm")
        return algorithm

    @staticmethod
    def get_private_key_algorithm(private_key: str) -> str:
        payload = _loads_json(private_key)
        algorithm = payload.get("algorithm")
        if not isinstance(algorithm, str) or not algorithm:
            raise ValueError("private key is missing an algorithm")
        return algorithm

    @staticmethod
    def inspect_public_key(public_key: str) -> Dict[str, object]:
        algorithm = QuantumSafeSignature.get_public_key_algorithm(public_key)

        if algorithm == WOTS_ALGORITHM:
            parsed = _parse_wots_key(public_key, WOTS_PUBLIC_TYPE)
            return {
                "algorithm": WOTS_ALGORITHM,
                "slots": parsed["slots"],
                "key_bytes": len(parsed["key_material"]),
            }

        payload = _loads_json(public_key)
        if payload.get("type") != WOTS_PUBLIC_TYPE:
            raise ValueError("public key has invalid type")
        if algorithm not in {ML_DSA_ALGORITHM, SPHINCS_ALGORITHM, "XMSS-SHA2_10_256"}:
            raise ValueError("unsupported public key algorithm")

        key_material = _b64url_decode(str(payload.get("key", "")))
        if not key_material:
            raise ValueError("public key material is empty")

        if (
            algorithm == ML_DSA_ALGORITHM
            and PQCRYPTO_ML_DSA_AVAILABLE
            and len(key_material) != ml_dsa_65.PUBLIC_KEY_SIZE  # type: ignore[union-attr]
        ):
            raise ValueError("ML-DSA public key length is invalid")

        if (
            algorithm == SPHINCS_ALGORITHM
            and PQCRYPTO_SPHINCS_AVAILABLE
            and len(key_material) != sphincs_sha2_256f_simple.PUBLIC_KEY_SIZE  # type: ignore[union-attr]
        ):
            raise ValueError("SPHINCS+ public key length is invalid")

        return {
            "algorithm": algorithm,
            "slots": None,
            "key_bytes": len(key_material),
        }

    @staticmethod
    def get_public_key_capacity(public_key: str) -> Optional[int]:
        info = QuantumSafeSignature.inspect_public_key(public_key)
        slots = info.get("slots")
        return int(slots) if slots is not None else None

    @staticmethod
    def generate_nonce(length: int = NONCE_LENGTH) -> str:
        return secrets.token_bytes(length).hex()

    @staticmethod
    def encode_key(key: str) -> str:
        return base64.b64encode(bytes.fromhex(key)).decode("utf-8")

    @staticmethod
    def decode_key(encoded_key: str) -> str:
        return base64.b64decode(encoded_key.encode("utf-8")).hex()


# ============================================================================
# Request Helpers
# ============================================================================

def get_client_ip(request, trust_proxy_headers: bool = False) -> str:
    forwarded_for = request.headers.getlist("X-Forwarded-For")
    if trust_proxy_headers and forwarded_for:
        return forwarded_for[0].split(",", 1)[0].strip()
    return request.remote_addr or "unknown"


def get_user_agent(request) -> str:
    return request.headers.get("User-Agent", "unknown")


print(f"\n[CRYPTO] Best installed backend: {QuantumSafeSignature.get_backend()}")
print(f"[CRYPTO] Default signature algorithm: {QuantumSafeSignature.SIGNATURE_ALGORITHM}\n")
