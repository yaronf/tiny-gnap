#!/bin/bash

# create config database
go test ./rc &>  /dev/null || echo "DB created"
# Ignore errors

go test ./as &
if [ $? ]; then
	echo AS failed
	exit 1
fi

go test ./rc || exit 1
if [ $? ]; then
	echo RC failed
	exit 1
fi
