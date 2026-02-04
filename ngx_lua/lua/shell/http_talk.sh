#!/usr/bin/env bash
ApiUrl=$1
Msg=$2

curl -s -H "Content-Type:application/json" -X POST --data "${Msg}" "${ApiUrl}"
