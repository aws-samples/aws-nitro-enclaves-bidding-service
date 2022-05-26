# AWS Nitro Enclaves Bidding Service

## Introduction
This Proof of Concept (POC) bidding service application will demonstrate the use of AWS Nitro Enclaves to perform computation on multiple sensitive datasets. We will utilize Nitro Enclaves with AWS Key Management Service (KMS) to create an isolated compute environment, allow the environment to process encrypted datasets from multiple parties, and return an output. The POC application will be centered around the scenario of real estate bidding where a bidding service will take in encrypted bids from two buyers and determine the highest bid on each property without disclosing the bid amounts to each buyer. Instructions are given for three different roles: Buyer1, Buyer2, and the Bidding Service. You can create three separate accounts for each role or use a single account for all the roles.

<p align="center">
  <img width="629" height="600" src="/BiddingServiceApplicationDiagram.png">
</p>

## How it works
The POC bidding service application is a single python script that contains the implementation for both the parent instance and the enclave instance. The parent instance is responsible for retrieving the encrypted bids from S3, sending a Decrypt message to the enclave instance with the encrypted bids, and writing the output of the Decrypt message to its own S3 bucket. The enclave instance is responsible for calling KMS to decrypt the bids, determining the highest bidder, and returning the output to the parent. Communication between the parent and the enclave is done through a VSockHandler class which handles low level functions of a VSock connection. A detailed look at the code is shown below:

### Parent instance 

Retrieving encrypted bids from S3.
```
data = s3client.get_object(Bucket=bucketBuyer1, Key="encrypted.csv")
for row in csv.DictReader(codecs.getreader("utf-8")(data["Body"])):
    buyer1data.append(row['[].bid'])

data2 = s3client.get_object(Bucket=bucketBuyer2, Key="encrypted.csv")
for row in csv.DictReader(codecs.getreader("utf-8")(data2["Body"])):
    buyer2data.append(row['[].bid'])
```

The parent will take the encrypted bids and combine them in a Decrypt message that is sent to the enclave through an instance of the VsockHandler class.
```
result = VsockConnection.request(0,"Decrypt,"+buyer1data[i] + "," + buyer2data[i],True)
```

When all the results have been received, the results will be aggregrated and written to an output file in the bidding service's S3 bucket.
```
response = s3client.put_object(
    Bucket=bucketBiddingService, Key="output.csv", Body=csv_buffer.getvalue()
)
```

### Enclave instance

Decrypting the bids and determining the winner.
```
plaintext1 = self.decryptText(dataStr[2]);
plaintext2 = self.decryptText(dataStr[3]);
returnMsg = "Buyer1 Wins"
if int(plaintext2)>int(plaintext1):
    returnMsg = "Buyer2 Wins"
```

The decryptText function will call KMS to decrypt the bids through the KMS proxy running on the parent instance.
```
def decryptText(self, data):
    proc = subprocess.Popen(
        [
            "/usr/src/app/kmstool_enclave_cli",
            "--region", "us-west-2",
            "--proxy-port", "8000",
            "--aws-access-key-id", self.accessKey,
            "--aws-secret-access-key", self.secretKey,
            "--aws-session-token", self.sessionKey,
            "--ciphertext", data,
        ],
        stdout=subprocess.PIPE
    )
    plaintext = proc.communicate()[0].decode()
    base64_bytes = plaintext.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    message = message_bytes.decode('ascii')
    return message
```

The result of the bidding is returned to the parent through an instance of the VsockHandler class.
```
self.vsockhandle.request(dataStr[0],returnMsg,False)
```

### VsockHandler class
The VsockHandler class handles the low level functions of a VSock connction. This includes having a separate thread for sending and receiving messages, message queuing, and optional waiting on responses. 

Separate threads for sending and receiving messages. The threads will utilize message queues in the VsockHandler class to track sent and received messages.
```
def listener_vsock_thread(self, port):
    self.listenerObject = VsockListener(self)
    self.listenerObject.bind(port)
    self.listenerObject.recv_data(self.enclave,port)

def sender_vsock_thread(self, cid, port):
    while self.run:
        for i in list(self.requestQueue):
            self.requestQueue.remove(i);
            msg = str(i.msgID) + "," + i.msg
            print("SEND: Sending msg: "+msg+" to "+str(cid)+":"+str(port))
            client = VsockStream(self)
            endpoint = (cid, port)
            client.connect(endpoint)
            client.send_data(msg.encode())
        time.sleep(0.5)
```

Message queuing to ensure message delivery ordering.
```
self.requestQueue.append(socketMessage(msgID,msg))
...
self.responseQueue.append(socketMessage(msgID,msg))
```

When sending a message, waiting on the response is controlled by the waitResp parameter. This is useful as the parent needs to wait on the response from the enclave for a Decypt message while the enclave would not need to wait on the response from the parent when sending the result of the bidding.
```
def request(self, msgID, msg, waitResp):
    if waitResp:
        msgID = self.requestID
        self.requestID += 1
    self.requestQueue.append(socketMessage(msgID,msg))
    msgNotReady = waitResp
    returnMsg = ""
    while msgNotReady:
        for i in list(self.responseQueue):
            if int(i.msgID) == int(msgID):
                returnMsg = i.msg
                self.responseQueue.remove(i)
                msgNotReady = False
        time.sleep(0.5)
    return returnMsg
```

## Deployment

### Requirements
* AWS CLI
* One or more AWS Account(s)

### Create AWS Resources and Encrypted Bid Files
We will be creating AWS Resources for each of the roles and then creating our encrypted bid files which will be used during the bidding process.

#### Buyer1
1. Create a S3 bucket. See these [instructions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/create-bucket-overview.html "instructions") Note the name and ARN.
2. Create a KMS Customer managed key (CMK). See these [instructions](https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html#create-symmetric-cmk "instructions") for more details. Note the KeyID and ARN of this key.
3. In this POC we will be making three bids on three different properties. Determine your bids for each property and then encrypt the bids using aws-cli. See [AWS documentation](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html "instructions") for more details about aws-cli. For the example I will be bidding $100,000 on the first property, $200,000 on the second property, and $150,000 on the third property.

```
aws kms encrypt --key-id <KMS CMK KeyID> --plaintext 100000
Returns: <Encrypted Bid 1>
aws kms encrypt --key-id <KMS CMK KeyID> --plaintext 200000
Returns: <Encrypted Bid 2>
aws kms encrypt --key-id <KMS CMK KeyID> --plaintext 150000
Returns: <Encrypted Bid 3>
```
4. Now create a file called encrypted.csv:
```
[].contract,[].bid
1,<Encrypted Bid 1>
2,<Encrypted Bid 2>
3,<Encrypted Bid 3>
```
5. Place this file in the S3 bucket you created earlier. 

#### Buyer2
Buyer2 should repeat the steps above to create their AWS resources and generate their own file. Ensure the bid amounts are different.

#### Bidding Service
1. Create a S3 bucket. See these [instructions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/create-bucket-overview.html "instructions") Note the name and ARN.
2. Follow these [instructions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#working-with-iam-roles "instructions") to create an IAM EC2 instance role.
3. Note the ARN for the IAM role.

### IAM Setup
At this point you should have the following ARNs from the previous steps:
- Buyer1 BUCKET ARN: S3 bucket arn for Buyer1 account.
- Buyer2 BUCKET ARN: S3 bucket arn for Buyer2 account.
- Bidding Service BUCKET ARN: S3 bucket arn for Bidding Service account.
- INSTANCE ROLE ARN: IAM role arn assigned to EC2 instance.
- Buyer1 KMS CMK ARN: KMS CMK arn for Buyer1.
- Buyer2 KMS CMK ARN: KMS CMK arn for Buyer2.

#### Buyer1 and Buyer2
1. Follow these [instructions](https://docs.aws.amazon.com/AmazonS3/latest/userguide/add-bucket-policy.html "instructions") to add the following bucket policy to the Buyer's S3 bucket:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "<INSTANCE ROLE ARN>"
            },
            "Action": "s3:*",
            "Resource": "<Buyer's BUCKET ARN>/*"
        }
    ]
}
```

#### Bidding Service
1. Follow these [instructions](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_manage-attach-detach.html#add-policies-console "instructions") to add the following IAM policy to the IAM EC2 instance role:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "s3:PutObject",
                "s3:GetObject",
                "sts:AssumeRole",
                "kms:Decrypt"
            ],
            "Resource": [
                "<Buyer1 KMS CMK ARN>",
                "<Buyer2 KMS CMK ARN>",
                "<Buyer1 BUCKET ARN>/*",
                "<Buyer2 BUCKET ARN>/*",
                "<Bidding Service BUCKET ARN>/*",
                "<INSTANCE ROLE ARN>"
            ]
        }
    ]
}
```

### EC2 Instance Setup
#### Bidding Service
1. Launch an EC2 instance with the following settings:
    * AMI: Amazon Linux 2 AMI (HVM), SSD Volume Type, x86
    * Instance type: c5.2xlarge
    * IAM role: Choose the instance role created earlier
    * Enclave: Enable
2. Login to the EC2 instance.
3. Setup Docker and nitro-cli
```
sudo amazon-linux-extras install -y docker
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -a -G docker ec2-user
sudo amazon-linux-extras enable aws-nitro-enclaves-cli
sudo yum install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel
```
4. Allocate more memory to Nitro Enclaves by modifying /etc/nitro_enclaves/allocator.yaml:
```
memory_mib: 2048
```
5. Run this command to allocate the memory
```
sudo systemctl start nitro-enclaves-allocator.service && sudo systemctl enable nitro-enclaves-allocator.service
```
6. Setup Python3 and Pip
```
sudo yum install -y python3 python3-pip
```
7. Install Python dependencies
```
sudo pip3 install boto3 pandas
```
8. Start the vsock-proxy to allow KMS communication from the Enclave
```
sudo systemctl enable nitro-enclaves-vsock-proxy.service
```

### Bidding Service Application Setup
#### Bidding Service
1. Install git and clone this repository.
```
sudo yum install -y git
git clone https://github.com/Enclavet/nitro-enclave-bidding-service
```
2. Build the kmstool-enclave-cli by following the instructions here: [https://github.com/aws/aws-nitro-enclaves-sdk-c/tree/main/bin/kmstool-enclave-cli](https://github.com/aws/aws-nitro-enclaves-sdk-c/tree/main/bin/kmstool-enclave-cli "instructions")
3. After building the kmstool-enclave-cli, copy kmstool_enclave_cli and libnsm.so to your nitro-enclave-bidding-service directory.
4. Modify vsock-poc.py with the S3 bucket names and the IAM EC2 instance role. Note that the bucket names are defined instead of the ARNs. 
```
...
bucketBuyer1 = "<Buyer1 BUCKET NAME>"
bucketBuyer2 = "<Buyer2 BUCKET NAME>"
bucketBiddingService = "<Bidding Service BUCKET NAME>"
instanceRoleARN = "<INSTANCE ROLE ARN>"
...
```
5. Build the container
```
docker build -t vsock-poc .
```
6. Build the Enclave image
```
sudo nitro-cli build-enclave --docker-uri vsock-poc --output-file ~/vsock_poc.eif
```
If successful you should see output similar to below:
```
Enclave Image successfully created. 
{ "Measurements": 
  { "HashAlgorithm": "Sha384 { ... }", 
    "PCR0": "287b24930a9f0fe14b01a71ecdc00d8be8fad90f9834d547158854b8279c74095c43f8d7f047714e98deb7903f20e3dd", 
    "PCR1": "aca6e62ffbf5f7deccac452d7f8cee1b94048faf62afc16c8ab68c9fed8c38010c73a669f9a36e596032f0b973d21895", 
    "PCR2": "0315f483ae1220b5e023d8c80ff1e135edcca277e70860c31f3003b36e3b2aaec5d043c9ce3a679e3bbd5b3b93b61d6f" 
  } 
}
```
7. Save the PCR0 value for setting up the KMS key policies later in this document.

### KMS Key Policies Setup
#### Buyer1 and Buyer2
1. Follow these [instructions](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-modifying.html 'instructions') to modify the KMS CMK key policy for each Buyer. You will want to add the following statement to the key policy:
```
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
            "kms:RecipientAttestation:ImageSha384": "<PCR0 value>"
        }
    }
}
```

### Running the Bidding Service Application
#### Bidding Service
1. Start the Enclave
```
sudo nitro-cli run-enclave --eif-path ~/vsock_poc.eif --cpu-count 2 --memory 2048 --debug-mode
```
If successful, you will see similar output below:
```
Start allocating memory...
Started enclave with enclave-cid: 19, memory: 2048 MiB, cpu-ids: [1, 5]
{
  "EnclaveName": "vsock_poc",
  "EnclaveID": "i-0c3d696ac3c1f00dc-enc1802f51427d0db9",
  "ProcessID": 18647,
  "EnclaveCID": 19,
  "NumberOfCPUs": 2,
  "CPUIDs": [
    1,
    5
  ],
  "MemoryMiB": 2048
}
```
Note the EnclaveID and EnclaveCID.
2. Connect to the Enclave console using the EnclaveID:
```
sudo nitro-cli console --enclave-id <EnclaveID>
```
If you see similar output below, the application is ready to receive requests:
```
...
[    0.807515] nsm: loading out-of-tree module taints kernel.
[    0.807870] nsm: module verification failed: signature and/or required key missing - tainting kernel
[    0.812592] random: python3: uninitialized urandom read (24 bytes read)
Starting VsockConnection
```
3. Run the parent instance application
```
python3 vsock-poc.py parent <EnclaveCID> 5005
```
Output:
```
Starting VsockConnection
SEND: Sending msg: 0,SetCredential,<CredentialData> to 19:5005
RECEIVE: 0,1
Property 1
SEND: Sending msg: 1,Decrypt,<Buyer1 Property 1 encrypted bid>,<Buyer2 Property 1 encrypted bid> to 19:5005
RECEIVE: 1,Buyer1 Wins
Result: Buyer1 Wins
Property 2
SEND: Sending msg: 2,Decrypt,<Buyer1 Property 2 encrypted bid>,<Buyer2 Property 2 encrypted bid> to 19:5005
RECEIVE: 2,Buyer2 Wins
Result: Buyer2 Wins
Property 3
SEND: Sending msg: 3,Decrypt,<Buyer1 Property 3 encrypted bid>,<Buyer2 Property 3 encrypted bid> to 19:5005
RECEIVE: 3,Buyer1 Wins
Result: Buyer1 Wins
Successful S3 put_object response. Status - 200
```
4. An output file: output.csv should have been generated in the Bidding Service S3 bucket.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

