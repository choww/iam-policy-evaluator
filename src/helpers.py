import argparse
import sys
import yaml

from policyuniverse.arn import ARN


class InvalidARNException(Exception):
    #sys.tracebacklimit = 0 # omit error trace in error message
    pass

def validate_arn(input):
    arn = ARN(input)
    if arn.error: 
        raise InvalidARNException(f'`{input}` is an invalid AWS ARN')
   
    return arn

def get_input(args=sys.argv):
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-c",
        "--config", 
        default="config.yaml",
        help="Path to config file. Default is %(default)s",
    )

    parser.add_argument(
        "-a", 
        "--actions-for",
        help="Provide the AWS resource name for which to list all possible actions"
    )

    parser.add_argument(
        "--role-assumption-only",
        action="store_true",
        help="Skip analyzing permissions on resources, just return role assumption info for the given role"
    )

    params = parser.parse_args(args[1:])

    with open(params.config, 'r') as config_file: 
        config = yaml.safe_load(config_file)

        role = validate_arn(config['role_arn'])
        resource = validate_arn(config['resource']['arn'])
        service = resource.tech

        action = config['resource']['action'] or '*'
        
        params = {
            'resource': resource,
            'service': service, 
            'identity': role,
            'action': f'{service}:{action}',
            'aws_profiles': config['aws_profiles'],
            'role_assumption_only': params.role_assumption_only,
        }

        return params
