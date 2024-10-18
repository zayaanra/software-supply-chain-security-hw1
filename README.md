# Artifact Signer

## Project Description
This project will allow you to sign an artifact and upload its signature to a public instance of a transparency log. It will also verify the inclusion in the transparency log, along with verifying that the correct signature is stored in the transparency log.  Finally, it can verify the integrity of the transparency log at any point of time.

## Installation
1. Clone the repository
```
git clone git@github.com:zayaanra/software-supply-chain-security-hw1.git
```

2. Make sure you are in the root of the project directory and create a Python virtual environment. Make sure the latest version of Python is installed.
```
python -m venv venv
```

3. Activate the newly created virtual environment.
```
// Windows
venv/Scripts/activate

// Linux
source venv/bin/activate
```

4. Install the required dependencies (you need to have `pip` installed for this)
```
pip install -r requirements.txt
```

## Usage

### Sigstore and Cosign
To sign and upload an artifact using the Cosign tool, you can do:
```
cosign sign-blob <file> --bundle artifact.bundle
```
If you do not have Cosign installed and want further information on Cosign, please refer to its documentation: https://docs.sigstore.dev/

### Running the program
Once you have signed and uploaded an artifact, you can now use the command line tool provided by the project to perform a variety of functions. Please see below for example usages.

To fetch the latest checkpoint in the Rekor log:
```
python main.py -c
```

To verify that the artifact signature in the transparency log is correct:
```
python main.py --inclusion <log_index> --artifact <path_to_artifact>
```

To verify that the checkpoint added is consistent with the latest checkpoint using checkpoint details obtained when running `python main.py -c`:
```
python main.py --consistency --tree-id <previous_tree_id> --tree-size \
<previous_tree_size> --root-hash <previous_tree_root_hash>
```

Optionally, all commands can also be run with the `-d` or `--debug` flag to enable debug mode. In debug mode, extra information is printed out during execution. Debug mode is disabled by default.
```
python main.py -d
// or
python main.py --debug=True
```
