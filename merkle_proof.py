"""
Provides a Hasher class that can compute hashes (default is SHA-256).
It also contains functions to help verify inclusion and consistency proofs.

Variables:
    DefaultHasher

Classes:
    Hasher
    RootMismatchError

Functions:

    Hasher.new()
    Hasher.empty_root()
    Hasher.hash_leaf(leaf)
    Hasher.hash_children(left, right)
    Hasher.size()

    verify_consistency(hasher, size1, size2, proof, root1, root2)
    verify_match(calculated, expected)
    decomp_incl_proof(index, size)
    inner_proof_size(index, size)
    chain_inner(hasher, seed, proof, index)
    chain_inner_right(hasher, seed, proof, index)
    chain_border_right(hasher, seed, proof)
    root_from_inclusion_proof(hasher, index, size, leaf_hash, proof)
    verify_inclusion(hasher, index, size, leaf_hash, proof, root, debug=False)
    compute_leaf_hash(body)
"""

import hashlib
import binascii
import base64

# domain separation prefixes according to the RFC
RFC6962_LEAF_HASH_PREFIX = 0
RFC6962_NODE_HASH_PREFIX = 1


class Hasher:
    """Hasher class that can compute hashes (default is SHA-256).

    Methods:
        new()
        empty_root()
        hash_leaf(leaf)
        hash_children(left, right)
        size()
    """

    def __init__(self, hash_func=hashlib.sha256):
        """Initializes Hasher object

        Args:
            hash_func (Any, optional): The hash function for this Hasher.
            Defaults to hashlib.sha256.
        """
        self.hash_func = hash_func

    def new(self):
        """Returns the hash function

        Returns:
            hash_func (Any, optional): The hash function for this Hasher.
        """
        return self.hash_func()

    def empty_root(self):
        """Returns the digest of an empty hash

        Returns:
            digest (str): A digest for the empty hash
        """
        return self.new().digest()

    def hash_leaf(self, leaf):
        """Returns the hash of a leaf

        Args:
            leaf (Any): The leaf

        Returns:
            digest (str): The hash of the leaf
        """
        h = self.new()
        h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))
        h.update(leaf)
        return h.digest()

    def hash_children(self, left, right):
        """Returns the hash of two children

        Args:
            left (Any): The left child
            right (Any): The right child

        Returns:
            digest (str): The hash of the children
        """
        h = self.new()
        b = bytes([RFC6962_NODE_HASH_PREFIX]) + left + right
        h.update(b)
        return h.digest()

    def size(self):
        """Returns the size of the digest the hash function can produce

        Returns:
            digest_size (Any): Size of the digest of the hash function
        """
        return self.new().digest_size


# DefaultHasher is a SHA256 based LogHasher
DefaultHasher = Hasher(hashlib.sha256)


def verify_consistency(hasher, sizes, proof, roots):
    """Verifies consistency between an old checkpoint and latest checkpoint

    Args:
        hasher (Hasher): A Hasher object with some hashing function
        size1 (_type_): _description_
        size2 (_type_): _description_
        proof (list): A list of hashes
        root1 (str): Old tree root hash
        root2 (str): Latest tree root hash

    Raises:
        ValueError: Raised if the latest tree size < old tree size
        ValueError: Raised if both tree sizes are equal but the proof is not empty
        ValueError: Raised if proof is not empty
        ValueError: Raised if proof is not empty
        ValueError: Raised if proof is of incorrect size
    """
    # change format of args to be bytearray instead of hex strings
    root1 = bytes.fromhex(roots[0])
    root2 = bytes.fromhex(roots[1])
    bytearray_proof = []
    for elem in proof:
        bytearray_proof.append(bytes.fromhex(elem))

    if sizes[1] < sizes[0]:
        raise ValueError(f"size2 ({sizes[1]}) < size1 ({sizes[0]})")
    if sizes[0] == sizes[1]:
        if bytearray_proof:
            raise ValueError("size1=size2, but bytearray_proof is not empty")
        verify_match(root1, root2)
        return
    if sizes[0] == 0:
        if bytearray_proof:
            raise ValueError(
                f"expected empty bytearray_proof, but got {len(bytearray_proof)} components"
            )
        return
    if not bytearray_proof:
        raise ValueError("empty bytearray_proof")

    inner, border = decomp_incl_proof(sizes[0] - 1, sizes[1])
    shift = (sizes[0] & -sizes[0]).bit_length() - 1
    inner -= shift

    if sizes[0] == 1 << shift:
        seed, start = root1, 0
    else:
        seed, start = bytearray_proof[0], 1

    if len(bytearray_proof) != start + inner + border:
        raise ValueError(
            f"wrong bytearray_proof size {len(bytearray_proof)}, want {start + inner + border}"
        )

    bytearray_proof = bytearray_proof[start:]

    hash1 = chain_inner_right(
        hasher, seed, bytearray_proof[:inner], (sizes[0] - 1) >> shift
    )
    hash1 = chain_border_right(hasher, hash1, bytearray_proof[inner:])
    verify_match(hash1, root1)

    hash2 = chain_inner(hasher, seed, bytearray_proof[:inner], (sizes[0] - 1) >> shift)
    hash2 = chain_border_right(hasher, hash2, bytearray_proof[inner:])
    verify_match(hash2, root2)


def verify_match(calculated, expected):
    """Verifies that the two hashes are equal

    Args:
        calculated (str): The calculated hash
        expected (str): The expected hash

    Raises:
        RootMismatchError: Raised if the calculated hash does not match the expected hash
    """
    if calculated != expected:
        raise RootMismatchError(expected, calculated)


def decomp_incl_proof(index, size):
    """Decomposes an inclusion proof into inner and border parts

    Args:
        index (int): Index in the tree
        size (int): Size of the tree

    Returns:
        (int, int): Return the inner and border part as a tuple
    """
    inner = inner_proof_size(index, size)
    border = bin(index >> inner).count("1")
    return inner, border


def inner_proof_size(index, size):
    """Computes the size of the inner proof

    Args:
        index (int): index in the tree
        size (int): size of the tree

    Returns:
        int: Returns the size of the inner proof
    """
    return (index ^ (size - 1)).bit_length()


def chain_inner(hasher, seed, proof, index):
    """Computes a new seed using the given hasher for the inner proof

    Args:
        hasher (Hasher): The Hasher object
        seed (bytearray): Seed for the hasher
        proof (list): List of hashes
        index (int): Index in the tree

    Returns:
        seed: The new seed
    """
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 0:
            seed = hasher.hash_children(seed, h)
        else:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_inner_right(hasher, seed, proof, index):
    """Computes a new seed using the given hasher for the inner right proof

    Args:
        hasher (Hasher): The Hasher object
        seed (bytearray): Seed for the hasher
        proof (list): List of hashes
        index (int): Index in the tree

    Returns:
        seed: The new seed
    """
    for i, h in enumerate(proof):
        if (index >> i) & 1 == 1:
            seed = hasher.hash_children(h, seed)
    return seed


def chain_border_right(hasher, seed, proof):
    """Computes a new seed using the given hasher for the border right proof

    Args:
        hasher (Hasher): The Hasher object
        seed (bytearray): Seed for the hasher
        proof (list): List of hashes

    Returns:
        seed: The new seed
    """
    for h in proof:
        seed = hasher.hash_children(h, seed)
    return seed


class RootMismatchError(Exception):
    """A custom exception for when the calculated root does not match the expected root

    Args:
        Exception (BaseException): The base exception for which this exception is derived from
    """

    def __init__(self, expected_root, calculated_root):
        self.expected_root = binascii.hexlify(bytearray(expected_root))
        self.calculated_root = binascii.hexlify(bytearray(calculated_root))

    def __str__(self):
        return (
            f"calculated root:\n{self.calculated_root}\n "
            "does not match expected root:\n{self.expected_root}"
        )


def root_from_inclusion_proof(hasher, index, size, leaf_hash, proof):
    """Computes the root hash from an inclusion proof

    Args:
        hasher (Hasher): The Hasher object
        index (int): Index in the tree
        size (int): Size of the tree
        leaf_hash (str): Hash of the given leaf
        proof (list): List of hashes

    Raises:
        ValueError: Raised if the index is beyond the size
        ValueError: Raised if leaf hash size is not equal to the hasher size
        ValueError: Raised if the proof size is not equal to the inner and border parts combined

    Returns:
        _type_: _description_
    """
    if index >= size:
        raise ValueError(f"index is beyond size: {index} >= {size}")

    if len(leaf_hash) != hasher.size():
        raise ValueError(
            f"leaf_hash has unexpected size {len(leaf_hash)}, want {hasher.size()}"
        )

    inner, border = decomp_incl_proof(index, size)
    if len(proof) != inner + border:
        raise ValueError(f"wrong proof size {len(proof)}, want {inner + border}")

    res = chain_inner(hasher, leaf_hash, proof[:inner], index)
    res = chain_border_right(hasher, res, proof[inner:])
    return res


def verify_inclusion(hasher, inclusion_proof, leaf_hash, debug=False):
    """Verifies that the given inclusion proof is valid

    Args:
        hasher (Hasher): The Hasher object
        index (int): Index in the tree
        size (int): Size of the tree
        leaf_hash (str): Hash of the given leaf
        proof (list): List of hashes
        root (str): Hash of the root
        debug (bool, optional): If True, print debug information. Defaults to False.
    """
    index, size, proof, root = (
        inclusion_proof["logIndex"],
        inclusion_proof["treeSize"],
        inclusion_proof["hashes"],
        inclusion_proof["rootHash"],
    )

    bytearray_proof = []
    for elem in proof:
        bytearray_proof.append(bytes.fromhex(elem))

    bytearray_root = bytes.fromhex(root)
    bytearray_leaf = bytes.fromhex(leaf_hash)
    calc_root = root_from_inclusion_proof(
        hasher, index, size, bytearray_leaf, bytearray_proof
    )
    verify_match(calc_root, bytearray_root)
    if debug:
        print("Calculated root hash", calc_root.hex())
        print("Given root hash", bytearray_root.hex())


# requires entry["body"] output for a log entry
# returns the leaf hash according to the rfc 6962 spec
def compute_leaf_hash(body):
    """Computes the hash of a leaf

    Args:
        body (str): The body for some log entry

    Returns:
        string: The hex digest of the computed leaf hash
    """
    entry_bytes = base64.b64decode(body)

    # create a new sha256 hash object
    h = hashlib.sha256()
    # write the leaf hash prefix
    h.update(bytes([RFC6962_LEAF_HASH_PREFIX]))

    # write the actual leaf data
    h.update(entry_bytes)

    # return the computed hash
    return h.hexdigest()
