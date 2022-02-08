#!/bin/bash

# create config database
go test ./rc >  /dev/null 2>&1 || echo "DB created"
# Ignore errors

go test ./as &
asPID=$!
if [ $? -ne 0 ]; then
	echo AS failed
	exit 1
fi

echo started AS as process $asPID

# Wait for server to start
sleep 3

go test ./rc || exit 1
if [ $? -ne 0 ]; then
	echo RC failed
	exit 1
fi
