run: 
	AWS_PROFILE=default poetry run python src/client.py -c config.yaml --skip-tf-repo --role-assumption-only
