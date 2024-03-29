from datetime import datetime as dt, timedelta as td  # Import datetime-related modules
from random import SystemRandom  # Import SystemRandom for secure random number generation
from typing import Union  # Import typing modules for type hints
from ..utils import curve_by_name, hash_numeric, mod  # Import utility functions
import secrets  # Import secrets module for cryptographic operations
import traceback  # Import traceback module for handling exceptions

from ..models import ZeroKnowledgeParams, ZeroKnowledgeSignature, ZeroKnowledgeProof, \
    ZeroKnowledgeData  # Import necessary models
from ..utils import to_bytes, to_str, bytes_to_int, int_to_bytes, dump_object  # Import utility functions

from ecpy.curves import Curve, Point  # Import elliptic curve related modules

import jwt  # Import jwt module for JSON Web Token operations

random = SystemRandom()  # Initialize a random number generator



class ZeroKnowledge:
    """
    Class implementing zero-knowledge authentication scheme.
    """

    def __init__(self,
                 params: ZeroKnowledgeParams,
                 secret: bytes = None,
                 algorithm: str = "HB2S",
                 issuer: str = "zk-call") -> None:
        """
        Initialize the curve with the given parameters
        """
        self._obj_curve = curve_by_name(params.curve)  # Retrieve the curve object
        if not self._obj_curve:
            raise ValueError("The curve '{}' is invalid".format(params.curve))
        self._params = params  # Store the parameters
        self._bits = self._obj_curve.field.bit_length()  # Get the number of bits for the curve
        self._secret = secret  # Store the secret key
        self._algorithm = algorithm  # Store the algorithm for JWT
        self._issuer = issuer  # Store the issuer name for JWT

    def generate_jwt(self, signature: ZeroKnowledgeSignature, exp: td = td(seconds=10)) -> Union[str, None]:
        """
        Generate a JSON Web Token (JWT) using the provided signature and expiration time.
        """
        if self._secret:
            now = dt.utcnow()  # Get the current UTC time
            return to_str(jwt.encode({  # Encode the JWT payload
                "signature": dump_object(signature),  # Dump the signature object
                "iat": now, "nbf": now, "exp": now + exp, "iss": self._issuer,  # Set JWT claims
            }, self._secret, algorithm=self._algorithm))  # Encode JWT using secret key

    def verify_jwt(self, tok: bytes) -> Union[dict, None]:
        """
        Verify a JSON Web Token (JWT) and return decoded data if valid.
        """
        if self._secret:
            try:
                return jwt.decode(  # Decode JWT
                    to_str(tok), self._secret,
                    iss=self._issuer, algorithms=[self._algorithm],
                )
            except (jwt.exceptions.ExpiredSignatureError, jwt.exceptions.DecodeError) as e:
                traceback.print_exc()  # Print traceback in case of errors
                pass
            except Exception as e:
                traceback.print_exc()  # Print traceback in case of errors

    @property
    def params(self) -> ZeroKnowledgeParams:
        """
        Get zero-knowledge parameters.
        """
        return self._params

    @property
    def salt(self) -> bytes:
        """
        Get salt used in the authentication.
        """
        return self._params.salt

    @property
    def curve(self) -> Curve:
        """
        Get the elliptic curve used for cryptography.
        """
        return self._obj_curve

    @staticmethod
    def new(curve_name: str = "Ed25519", hash_alg: str = "blake2b",
            jwt_secret: bytes = None, jwt_alg: str = "HB2B",
            salt_size: int = 16) -> 'ZeroKnowledge':
        """
        Create a new instance of "Zero-Knowledge" with specified parameters.
        """
        curve = curve_by_name(curve_name)  # Get the curve object
        if curve is None:
            raise ValueError("Invalid Curve Name")  # Raise error for invalid curve name

        return ZeroKnowledge(  # Return a new instance of "Zero-Knowledge"
            ZeroKnowledgeParams(  # Initialize "Zero-Knowledge"Params object
                algorithm=hash_alg,  # Set hashing algorithm
                curve=curve_name,  # Set elliptic curve name
                salt=secrets.token_bytes(salt_size),  # Generate salt
            ),
            secret=jwt_secret,  # Set JWT secret
            algorithm=jwt_alg,  # Set JWT algorithm
        )

    def _to_point(self, value: Union[int, bytes, ZeroKnowledgeSignature]) -> Point:
        """
        Convert a value to a point on the elliptic curve.
        """
        return self.curve.decode_point(to_bytes(
            value.signature if isinstance(value, ZeroKnowledgeSignature) else value
        ))

    def token(self) -> bytes:
        """
        Generate a random token.
        """
        return secrets.token_bytes(
            (self._bits + 7) >> 3
        )

    def hash(self, *values) -> int:
        """
        Hash the values provided modulo the curve order
        """
        return mod(hash_numeric(*[
            v for v in values if v is not None
        ], self.salt, alg=self.params.algorithm), self.curve.order)

    def create_signature(self, secret: Union[str, bytes]) -> ZeroKnowledgeSignature:
        """
        Create a signature object using the provided secret key.
        """
        return ZeroKnowledgeSignature(
            params=self.params,
            signature=to_bytes(
                self.hash(secret) * self.curve.generator),
        )

    def create_proof(self, secret: Union[str, bytes], data: Union[int, str, bytes] = None) -> ZeroKnowledgeProof:
        """
        Create a proof object using the provided secret key and optional data.
        """
        key = self.hash(secret)  # Compute hash of the secret key
        r = secrets.randbits(self._bits)  # Generate a random integer
        R = r * self.curve.generator  # Compute a point on the curve
        c = self.hash(data, R)  # Compute hash of the data and R
        m = mod(r - (c * key), self.curve.order)  # Compute m
        return ZeroKnowledgeProof(params=self.params, c=int_to_bytes(c), m=int_to_bytes(m))  # Return the proof object

    def sign(self, secret: Union[str, bytes], data: Union[int, str, bytes]) -> ZeroKnowledgeData:
        """
        Sign the provided data using the secret key.
        """
        data = to_str(data)  # Convert data to string
        return ZeroKnowledgeData(  # Create a "Zero-Knowledge"Data object
            data=data,
            proof=self.create_proof(secret, data),  # Create proof for the data
        )

    @staticmethod
    def signature_is_valid(signature: ZeroKnowledgeSignature) -> bool:
        """
        Check if the signature is valid.
        """
        try:
            zk = ZeroKnowledge(signature.params)  # Create "Zero-Knowledge" object
            return zk.curve.is_on_curve(zk._to_point(signature))  # Check if the signature is valid
        except:
            return False

    def verify(self,
               challenge: Union[ZeroKnowledgeData, ZeroKnowledgeProof],
               signature: ZeroKnowledgeSignature,
               data: Union[str, bytes, int] = "") -> bool:
        """
        Verify the authenticity of the provided challenge data against the given signature.
        """
        if isinstance(challenge, ZeroKnowledgeProof):  # Check if the challenge is a proof
            data, proof = data, challenge
        elif isinstance(challenge, ZeroKnowledgeData):  # Check if the challenge is data
            data, proof = challenge.data, challenge.proof
        else:
            raise TypeError("Invalid challenge type provided")  # Raise error for invalid challenge type
        c = bytes_to_int(proof.c)  # Convert proof.c to an integer
        p: Point = (bytes_to_int(proof.m) * self.curve.generator) \
                   + (c * self._to_point(signature))  # Compute the point
        return c == self.hash(data, p)  # Compare c with hash of data and point

    def login(self, login_data: ZeroKnowledgeData) -> bool:
        """
        Perform a login using the provided login data.
        """
        data = self.verify_jwt(login_data.data)  # Verify JWT token from login data
        return data and self.verify(  # Check if data is valid and verify the login
            login_data,
            ZeroKnowledgeSignature.from_json(data.get("signature")),  # Convert JSON signature to "Zero-Knowledge" Signature object
        )
