#!/bin/bash -l

echo "scitt-client_id:       " ${1}
echo "scitt-scitt-secret:    " ${2}
echo "feed:                  " ${3}
echo "payload:               " ${4}
echo "signed-statement-file: " ${5}
echo "receipt-file:          " ${6}
echo "signing-key-file:      " ${7}
echo "issuer:                " ${8}

# echo "Create an access token"
/scripts/create-token.sh ${1} ${2}

# echo "Test permissions with the assets API"
# ./query-assets.sh
echo "payload:"
cat ${4}

echo "create_signed_statement.py"

python /scripts/create_signed_statement.py \
  --feed ${3} \
  --payload ${4} \
  --output-file ${5} \
  --signing-key-file ${7} \
  --issuer ${8}

echo "output-file/signed-statement: " ${5}
cat ${5}

echo "bearer-token.txt"
cat ./bearer-token.txt

echo "POST to https://app.datatrails.ai/archivist/v1/publicscitt/entries"

curl -v -X POST -H @./bearer-token.txt \
                --data-binary @${5} \
                https://app.datatrails.ai/archivist/v1/publicscitt/entries

OPERATION_ID=$(curl -v -X POST -H @./bearer-token.txt \
                --data-binary @${5} \
                https://app.datatrails.ai/archivist/v1/publicscitt/entries \
                | jq -r .operationID)

echo "OPERATION_ID :" $OPERATION_ID

ENTRY_ID=$(python /scripts/check_operation_status.py --operation-id $OPERATION_ID)
echo "ENTRY_ID :" $ENTRY_ID

curl -H @./bearer-token.txt \
  https://app.datatrails.ai/archivist/v2/publicassets/-/events?event_attributes.feed_id=$FEED | jq
