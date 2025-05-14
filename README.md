# IAM Policy Evaluator

For evaluating AWS IAM role permissions

## Requirements
* Python 3.10+
* [Poetry](https://python-poetry.org/docs/#installation)
* IAM roles created through terraform and stored in a github repo

## Set up
```sh
# start virtualenv
poetry shell

# install dependencies
poetry install
```

## Usage
```sh
# create a copy of the example yaml config and update values accordingly
cp config.yaml.example config.yaml

# specify the AWS credentials to use for this tool
export AWS_PROFILE=<PROFILE-NAME>

make run
```
