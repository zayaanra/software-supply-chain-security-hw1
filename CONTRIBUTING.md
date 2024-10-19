# Contributing to Artifact Signer
The following is a set of guidelines to contribute to Artifact Signer.

## Coding Style Guidelines
If you plan on making any contributions to this repository, it is important to adhere to the coding style so that the code is not hard to read and easily maintainable. All code in this repository is in Python and as a result, follows the PEP 8 guidelines for writing Python code.

If you are unsure of PEP 8, please refer to: https://peps.python.org/pep-0008/
Furthermore, there are several static analysis tools that can help you write cleaner and better Python code. You can use Ruff and pylint in tandem, both linters built for analyzing and reformatting Python code. 

Ruff: https://github.com/astral-sh/ruff
pylint: https://pylint.readthedocs.io/en/stable/

When coding, also be sure to add docstrings at the beginning of every file, class, method, and functions.

## Reporting Issues
You can raise issues. Please be sure to include the correct label for the issue. There is no specific format to adhere to for the description but in general, please provide a complete and intensive description regarding the problem at hand. For example, if it is a bug that you have found, make sure to provide the steps required to recreate the bug.

## Pull Requests
You can also make a pull request. When you do make one, make sure to specify why you are doing so. For example, are you creating a pull request to update documentation, changing functionality, improving performance, or something else? Similar to raising issues, please provide a detailed and intesive description of the pull request.

## Adding Test Cases
Tests should be added in a `tests/` directory located in the root of the project. Test filenames should also be in the format `test_<test_name>.py`. `pytest` is the official testing framework for this project. Refer to its documentation for more: https://docs.pytest.org/en/stable/

## Commit Messages
If you are making a commit, please use an appropiate commit message. For example, if you are making a change that adds a test, the commit message should be something like: `git commit -m "Adding test case <testcase_name> to test <functionality>"`. Please be descriptive but concise.

