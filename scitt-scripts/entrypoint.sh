#!/bin/bash -l

set -e

# echo "content-type:              " ${1}
# echo "payload-file:              " ${2}
# echo "payload-location"          " ${3}
# echo "subject:                   " ${4}
# echo "transparent-statement-file:" ${5}

CONTENT_TYPE=${1}
PAYLOAD_FILE=${2}
PAYLOAD_LOCATION=${3}
SUBJECT=${5}
TRANSPARENT_STATEMENT_FILE=${5}

SIGNED_STATEMENT_FILE="signed-statement.cbor"

TOKEN_FILE="./bearer-token.txt"

if [ ! -f $PAYLOAD_FILE ]; then
  echo "ERROR: Payload File: [$PAYLOAD_FILE] Not found!"
  exit 126
fi

# echo "Create an access token"

/scripts/create-token.sh $TOKEN_FILE

if [ ! -f $TOKEN_FILE ]; then
  echo "ERROR: Token File: [$TOKEN_FILE] Not found!"
  exit 126
fi

echo "Sign a SCITT Statement with key protected in DigiCert Software Trust Manager"

python /scripts/create_signed_statement.py \
  --content-type $CONTENT_TYPE \
  --payload-file $PAYLOAD_FILE \
  --payload-location $PAYLOAD_LOCATION \
  --subject $SUBJECT \
  --output-file $SIGNED_STATEMENT_FILE

if [ ! -f $SIGNED_STATEMENT_FILE ]; then
  echo "ERROR: Signed Statement: [$SIGNED_STATEMENT_FILE] Not found!"
  exit 126
fi

echo "Register the SCITT Signed Statement to https://app.datatrails.ai/archivist/v1/publicscitt/entries"

python /scripts/register_signed_statement.py \
      --signed-statement-file $SIGNED_STATEMENT_FILE \
      --output-file $TRANSPARENT_STATEMENT_FILE \
      --log-level INFO

python /scripts/dump_cbor.py \
      --input $TRANSPARENT_STATEMENT_FILE

# curl https://app.datatrails.ai/archivist/v2/publicassets/-/events?event_attributes.feed_id=$SUBJECT | jq
