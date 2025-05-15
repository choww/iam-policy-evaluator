run: 
	AWS_PROFILE=default poetry run python -m src.client -c config.yaml  --role-assumption-only

test: 
	poetry run python3 -m unittest tests/*.py
