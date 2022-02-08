#!/bin/bash

# create config database
go test ./rc &>  /dev/null
# Ignore errors

go test ./as &
if [ $? ]; then
	exit 1
fi

go test ./rc || exit 1
