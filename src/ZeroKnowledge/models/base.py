
from dataclasses import dataclass, field
from dataclasses_json import dataclass_json, config
from ..utils import b64d, data_to_b64_str




@dataclass_json
@dataclass
class ZeroKnowledgeParams:
    """
    Parameters used to construct a "Zero-Knowledge" instance using a hashing scheme,
    a standard elliptic curve name, and a random salt
    """
    algorithm: str  # Hashing algorithm name
    curve: str  # Standard Elliptic Curve name to use
    salt: bytes = field(  # Random salt for the state
        metadata=config(encoder=data_to_b64_str, decoder=b64d),
    )


@dataclass_json
@dataclass
class ZeroKnowledgeSignature:
    """
    Cryptographic public signature used to verify future messages
    """
    params: ZeroKnowledgeParams  # Reference "Zero-Knowledge" Parameters
    signature: bytes = field(  # The public key derived from your original secret
        metadata=config(encoder=data_to_b64_str, decoder=b64d),
    )


@dataclass_json
@dataclass
class ZeroKnowledgeProof:
    """
    Cryptographic proof that can  be verified to ensure the private key used to create
    the proof is the same key used to generate the signature
    """
    params: ZeroKnowledgeParams  # Reference "Zero-Knowledge" Parameters
    c: bytes = field(  # The hash of the signed data and random point, R
        metadata=config(encoder=data_to_b64_str, decoder=b64d),
    )
    m: bytes = field(  # The offset from the secret `r` (`R=r*g`)  from c * Hash(secret)
        metadata=config(encoder=data_to_b64_str, decoder=b64d),
    )


@dataclass_json
@dataclass
class ZeroKnowledgeData:
    """
    Wrapper to contain data  and a signed proof using the data
    """
    data: bytes = field(  # Signed data
        metadata=config(encoder=data_to_b64_str, decoder=b64d),
    )
    proof: ZeroKnowledgeProof
