#!/bin/bash

ENV_FILE="./auth-service/.env"

if ! [[ -f $ENV_FILE ]]; then
    echo "Error: .env file not found in auth-service directory"
    exit 1
fi

while IFS= read -r line; do
    if [[ -n "$line" && "$line" != \#* ]]; then
	key=$(echo $line | cut -d'=' -f1)
	value=$(echo $line | cut -d'=' -f2-)
	export $key=$value
    fi
done < <(grep -v '^#' "$ENV_FILE")

docker-compose build
docker-compose up
