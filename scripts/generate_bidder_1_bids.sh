read -p "Please provide your KMS Key ID:" KEYID

echo "[].contract,[].bid" > encrypted.csv
echo -n "1," >> encrypted.csv
aws kms encrypt --key-id "${KEYID}" --cli-binary-format raw-in-base64-out --plaintext "100000" | jq -r ".CiphertextBlob" >> encrypted.csv
echo -n "2," >> encrypted.csv
aws kms encrypt --key-id "${KEYID}" --cli-binary-format raw-in-base64-out --plaintext "200000" | jq -r ".CiphertextBlob" >> encrypted.csv
echo -n "3," >> encrypted.csv
aws kms encrypt --key-id "${KEYID}" --cli-binary-format raw-in-base64-out --plaintext "150000" | jq -r ".CiphertextBlob" >> encrypted.csv
