run: 
	AWS_PROFILE=default poetry run python src/client.py -c config.yaml --role-assumption-only

test: 
	poetry run python3 -m unittest tests/*.py
