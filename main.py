import argparse
import requests
import json
import ast

from util import extract_public_key, verify_artifact_signature, decode_base64
from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash

def get_log_entry(log_index, debug=False):
    if debug:
        print("Fetching log entry from log index", log_index)
    
    try:
        # verify that log index value is sane
        resp = requests.get(f"https://rekor.sigstore.dev/api/v1/log/entries?logIndex={log_index}")
        return resp.json()
    except:
        print("Failed to fetch log entry from log index", log_index)
        return None

def get_verification_proof(log_index, debug=False):
    # verify that log index value is sane
    if debug:
        print("Fetching verification proof from log index", log_index)
    
    log_entry = get_log_entry(log_index)
    if log_entry is None:
        return None
    else:
        key = list(log_entry.keys())[0]
        return log_entry[key]['verification']

def inclusion(log_index, artifact_filepath, debug=False):
    if debug:
        print("Verifying inclusion of log index", log_index, "with artifact", artifact_filepath)

    log_entry = get_log_entry(log_index)
    if log_entry is None:
        return

    try:
        key = list(log_entry.keys())[0]
        body = log_entry[key]['body']
        decoded = ast.literal_eval(decode_base64(body).decode("UTF-8"))
        
        signature_dict = decoded['spec']['signature']
        signature = decode_base64(signature_dict['content'])
        certificate = decode_base64(signature_dict['publicKey']['content'])

        # verify that log index and artifact filepath values are sane
        public_key = extract_public_key(certificate)
        verify_artifact_signature(signature, public_key, artifact_filepath)
        verification_proof = get_verification_proof(log_index)

        inclusion_proof = verification_proof['inclusionProof']
        hashes = inclusion_proof['hashes']
        tree_size = inclusion_proof['treeSize']
        index = inclusion_proof['logIndex']
        root_hash = inclusion_proof['rootHash']
        leaf_hash = compute_leaf_hash(body)

        verify_inclusion(DefaultHasher, index, tree_size, leaf_hash, hashes, root_hash, debug=True)
    except:
        print("Failed to verify inclusion of log index", log_index, "with artifact", artifact_filepath)

def get_latest_checkpoint(debug=False):
    if debug:
        print("Fetching latest checkpoint from Rekor Server public instance")


    # TODO - stable true or false

    try:
        resp = requests.get("https://rekor.sigstore.dev/api/v1/log?stable=true")
        content = resp.json()
        return content
    except:
        print("Failed to fetch latest checkpoint from Rekor Server public instance")
        return None

def consistency(prev_checkpoint, debug=False):
    # verify that prev checkpoint is not empty
    if not prev_checkpoint:
        print("No previous checkpoint to verify consistency with")
        return
    
    # TODO - idk how to do this part
    
    checkpoint = get_latest_checkpoint()
    latestTreeID, latestTreeSize, latestRoot = checkpoint['treeID'], checkpoint['treeSize'], checkpoint['rootHash']

    prevTreeSize, prevTreeID, prevRoot = prev_checkpoint['treeSize'], prev_checkpoint['treeID'], prev_checkpoint['rootHash']

    #try:
    resp = requests.get(f"https://rekor.sigstore.dev/api/v1/log/proof?lastSize={prevTreeSize}&treeID={prevTreeID}")
    content = resp.json()
    print(content)
    verify_consistency(DefaultHasher, prevTreeSize, latestTreeSize, content['hashes'], prevRoot, latestRoot)
    # except:
    #     print("Failed to fetch consistency proof from Rekor Server public instance")

def main():
    debug = False
    parser = argparse.ArgumentParser(description="Rekor Verifier")
    parser.add_argument('-d', '--debug', help='Debug mode',
                        required=False, action='store_true') # Default false
    parser.add_argument('-c', '--checkpoint', help='Obtain latest checkpoint\
                        from Rekor Server public instance',
                        required=False, action='store_true')
    parser.add_argument('--inclusion', help='Verify inclusion of an\
                        entry in the Rekor Transparency Log using log index\
                        and artifact filename.\
                        Usage: --inclusion 126574567',
                        required=False, type=int)
    parser.add_argument('--artifact', help='Artifact filepath for verifying\
                        signature',
                        required=False)
    parser.add_argument('--consistency', help='Verify consistency of a given\
                        checkpoint with the latest checkpoint.',
                        action='store_true')
    parser.add_argument('--tree-id', help='Tree ID for consistency proof',
                        required=False)
    parser.add_argument('--tree-size', help='Tree size for consistency proof',
                        required=False, type=int)
    parser.add_argument('--root-hash', help='Root hash for consistency proof',
                        required=False)
    args = parser.parse_args()
    if args.debug:
        debug = True
        print("enabled debug mode")
    if args.checkpoint:
        # get and print latest checkpoint from server
        # if debug is enabled, store it in a file checkpoint.json
        checkpoint = get_latest_checkpoint(debug)
        if debug:
            with open('checkpoint.json', 'w') as f:
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
        
        prev_checkpoint = {}
        prev_checkpoint["treeID"] = args.tree_id
        prev_checkpoint["treeSize"] = args.tree_size
        prev_checkpoint["rootHash"] = args.root_hash

        consistency(prev_checkpoint, debug)

if __name__ == "__main__":
    log_index = '128511781'
    #inclusion(log_index, "/home/zayaanra/Desktop/school/software-supply-chain-security/software-supply-chain-security-hw1/artifact.md")
    main()
