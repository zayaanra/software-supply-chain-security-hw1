"""
Verifies the inclusion of the entry in the transparency log, along with verifying that the
correct signature is stored in the transparency log.

Verifies the integrity of the transparency log at any point of time by verifying the
consistency between an older checkpoint and the latest checkpoint.

Functions:

    get_log_entry(log_index, debug=False)
    get_verification_proof(log_index, debug=False)
    inclusion(log_index, artifact_filepath, debug=False)
    consistency(prev_checkpoint, debug=False)
    get_latest_checkpoint(debug=False)
    main()

"""

import argparse
import json
import ast

import binascii
import requests

from util import extract_public_key, verify_artifact_signature, decode_base64
from merkle_proof import (
    DefaultHasher,
    verify_consistency,
    verify_inclusion,
    compute_leaf_hash,
    RootMismatchError,
)


def get_log_entry(log_index, debug=False):
    """This function returns the log entry associated with the given log index.

    Args:
        log_index (str): Index of the log entry in the transparency log.
        debug (bool, optional): If True, print debug messages. Defaults to False.

    Returns:
        (Any, None): Returns the log entry associated with the given log index, 
        or None if something went wrong.
    """
    if debug:
        print("Fetching log entry from log index", log_index)

    try:
        # verify that log index value is sane
        resp = requests.get(
            f"https://rekor.sigstore.dev/api/v1/log/entries?logIndex={log_index}",
            timeout=5
        )
        return resp.json()
    except requests.exceptions.RequestException as e:
        print(f"Failed to fetch log entry from log index {log_index}: {e}")
        print(f"Respone was: {resp.raise_for_status()}")
        return None


def get_verification_proof(log_index, debug=False):
    """This function returns the verification proof associated with the given log index.

    Args:
        log_index (str): Index of the log entry in the transparency log.
        debug (bool, optional): If True, print debug messages. Defaults to False.

    Returns:
        (dict, None): Returns the verification proof associated with the given log index 
        or None if something went wrong.
    """
    # verify that log index value is sane
    if debug:
        print("Fetching verification proof from log index", log_index)

    log_entry = get_log_entry(log_index)
    if log_entry is None:
        return None
    key = list(log_entry.keys())[0]
    return log_entry[key]["verification"]


def inclusion(log_index, artifact_filepath, debug=False):
    """This function verifies the inclusion of an artifact in the transparency log.
    It requires the use of the signature and certificate associated with the log entry.
    It also utilizes the verification proof associated with the log entry.

    Args:
        log_index (str): Index of the log entry in the transparency log.
        artifact_filepath (str): The filepath of the artifact.
        debug (bool, optional): If True, print debug messages. Defaults to False.
    """

    if debug:
        print(
            "Verifying inclusion of log index",
            log_index,
            "with artifact",
            artifact_filepath,
        )

    log_entry = get_log_entry(log_index)
    if log_entry is None:
        return

    try:
        key = list(log_entry.keys())[0]
        body = log_entry[key]["body"]
        decoded = ast.literal_eval(decode_base64(body).decode("UTF-8"))

        signature_dict = decoded["spec"]["signature"]
        signature = decode_base64(signature_dict["content"])
        certificate = decode_base64(signature_dict["publicKey"]["content"])

        # verify that log index and artifact filepath values are sane
        public_key = extract_public_key(certificate)
        verify_artifact_signature(signature, public_key, artifact_filepath)
        verification_proof = get_verification_proof(log_index)

        inclusion_proof = verification_proof["inclusionProof"]

        verify_inclusion(DefaultHasher, inclusion_proof, compute_leaf_hash(body), debug=debug)
    except (KeyError, ValueError, binascii.Error) as e:
        print(f"Failed to verify inclusion of log index {log_index}" \
              f"with artifact {artifact_filepath}: {e}")


def get_latest_checkpoint(debug=False):
    """Fetches the latest checkpoint from Rekor transparency log.

    Args:
        debug (bool, optional): If True, print debug messages. Defaults to False.

    Returns:
        (Any, None): Returns the latest checkpoint or None if something went wrong.
    """

    if debug:
        print("Fetching latest checkpoint from Rekor Server public instance")

    try:
        resp = requests.get("https://rekor.sigstore.dev/api/v1/log?stable=true", timeout=5)
        content = resp.json()
        return content
    except (requests.exceptions.RequestException, ValueError) as e:
        print(
            "Failed to fetch latest checkpoint from Rekor Server public instance: ", e
        )
        print("Response was: ", resp.raise_for_status())
        return None


def consistency(prev_checkpoint, debug=False):
    """Verifies consistency between an older checkpoint and the latest checkpoint.

    Args:
        prev_checkpoint (dict): Represents the previous checkpoint. It includes
        the treeSize, treeID, and rootHash.
        debug (bool, optional): If True, print debug messages. Defaults to False.
    """

    if debug:
        print("Verifying consistency between previous and latest checkpoints")
    # verify that prev checkpoint is not empty
    if not prev_checkpoint:
        print("No previous checkpoint to verify consistency with")
        return

    checkpoint = get_latest_checkpoint()
    latest_tree_size, latest_root = checkpoint["treeSize"], checkpoint["rootHash"]
    prev_tree_size, prev_tree_id, prev_root = (
        prev_checkpoint["treeSize"],
        prev_checkpoint["treeID"],
        prev_checkpoint["rootHash"],
    )

    try:
        resp = requests.get(
            ("https://rekor.sigstore.dev/" \
            "api/v1/log/proof?" \
            f"firstSize={latest_tree_size}&lastSize={prev_tree_size}&treeID={prev_tree_id}"),
            timeout=5
        )
        content = resp.json()
        verify_consistency(
            DefaultHasher,
            [prev_tree_size, latest_tree_size],
            content["hashes"],
            [prev_root, latest_root]
        )
    except (
        requests.exceptions.RequestException,
        RootMismatchError,
        KeyError,
        ValueError,
    ) as e:
        print(
            "Failed to verify consistency proof from Rekor Server public instance: ", e
        )
        print("Response was: ", resp.raise_for_status())


def main():
    """
    Main function. It parses the command line arguments, checks which flags are set,
    and calls the appropriate function to perform the desired action. Verification of the
    command line arguments is done as well.
    """

    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument(
        "-d", "--debug", help="Debug mode", required=False, action="store_true"
    )  # Default false
    parser.add_argument(
        "-c",
        "--checkpoint",
        help="Obtain latest checkpoint\
                        from Rekor Server public instance",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "--inclusion",
        help="Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567",
        required=False,
        type=int,
    )
    parser.add_argument(
        "--artifact",
        help="Artifact filepath for verifying\
                        signature",
        required=False,
    )
    parser.add_argument(
        "--consistency",
        help="Verify consistency of a given\
                        checkpoint with the latest checkpoint.",
        action="store_true",
    )
    parser.add_argument(
        "--tree-id", help="Tree ID for consistency proof", required=False
    )
    parser.add_argument(
        "--tree-size", help="Tree size for consistency proof", required=False, type=int
    )
    parser.add_argument(
        "--root-hash", help="Root hash for consistency proof", required=False
    )
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        if debug:
            with open("checkpoint.json", "w", encoding="utf-8") as f:
                json.dump(checkpoint, f, indent=4)
        print(json.dumps(checkpoint, indent=4))
    if args.inclusion:
        inclusion(args.inclusion, args.artifact, debug)
    if args.consistency:
        if not args.tree_id:
            print("please specify tree id for prev checkpoint")
            return
        if not args.tree_size:
            print("please specify tree size for prev checkpoint")
            return
        if not args.root_hash:
            print("please specify root hash for prev checkpoint")
            return

        # Validate arguments
        if not args.tree_id.isdigit():
            print("tree id must be an integer")
            return
        if not args.tree_size.isdigit():
            print("tree size must be an integer")
            return
        if len(args.root_hash) != 64:
            print("root hash must be 64 characters long")
            return

        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)


if __name__ == "__main__":
    main()
