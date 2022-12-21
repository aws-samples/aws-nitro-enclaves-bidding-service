PCR0=$(sudo nitro-cli describe-enclaves | jq -r .[0].Measurements.PCR0) 
PCR1=$(sudo nitro-cli describe-enclaves | jq -r .[0].Measurements.PCR1) 
PCR2=$(sudo nitro-cli describe-enclaves | jq -r .[0].Measurements.PCR2) 
 
cat <<EOF  
{ 
    "Sid": "Allow use of the key", 
    "Effect": "Allow", 
    "Principal": { 
        "AWS": "<INSTANCE ROLE ARN>" 
    }, 
    "Action": "kms:Decrypt", 
    "Resource": "*", 
    "Condition": { 
        "StringEqualsIgnoreCase": { 
            "kms:RecipientAttestation:ImageSha384": "${PCR0}", 
            "kms:RecipientAttestation:PCR1":"${PCR1}", 
            "kms:RecipientAttestation:PCR2":"${PCR2}" 
        } 
    } 
} 
EOF 