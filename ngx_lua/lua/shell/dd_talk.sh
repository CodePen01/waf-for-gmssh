#!/usr/bin/env bash
Token=$1
Secret=$2
Msg=$3

GetTimeStamp() {
    TimeStamp="$(date -u +"%s")000"
}

URLEncode() {
    for c in $(echo -n "${1}" | sed 's/[^\n]/&\n/g'); do
        case ${c} in
            [a-zA-Z0-9~._-]) printf "%s" "${c}" ;;
            *) printf "%%%02X" "'${c}" ;;
        esac
    done
}

GetTimeStamp
Sign=$(echo -en "${TimeStamp}\n${Secret}" | openssl dgst -sha256 -hmac "${Secret}" -binary | openssl base64)
Sign=$(URLEncode "${Sign}")
ApiUrl="${Token}&timestamp=${TimeStamp}&sign=${Sign}"
curl -s -H "Content-Type:application/json" -X POST --data "{\"msgtype\":\"text\",\"text\":{\"content\":\"${Msg}\"}}" "${ApiUrl}"
