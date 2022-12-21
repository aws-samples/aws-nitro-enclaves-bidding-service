#!/usr/local/bin/env python3

# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import io
import argparse
import socket
import sys
import subprocess
import threading
import time
import base64
import json

global bucketBuyer1
global bucketBuyer2
global bucketBiddingService
global instanceRoleARN
bucketBuyer1 = ""
bucketBuyer2 = ""
bucketBiddingService = ""
instanceRoleARN = ""
region = "us-west-1"

class VsockHandler:
    def __init__(self, cid, port, enclave):
        self.requestQueue = []
        self.responseQueue = []
        self.requestID = 0
        listenport = port
        sendport = port + 1
        if not enclave:
            listenport = port + 1
            sendport = port
        self.listener = threading.Thread(target=self.listener_vsock_thread, args=(listenport,))
        self.sender = threading.Thread(target=self.sender_vsock_thread, args=(cid,sendport,))
        self.enclave = enclave

    def start(self):
        self.run = True
        self.listener.start()
        self.sender.start()

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

    def response(self, msgID, msg):
        self.responseQueue.append(socketMessage(msgID,msg))

    def close(self):
        self.run = False
        self.listenerObject.close()

class VsockStream:
    """Client"""
    def __init__(self, vsockhandle, conn_tmo=5):
        self.vsockhandle = vsockhandle
        self.conn_tmo = conn_tmo

    def connect(self, endpoint):
        """Connect to the remote endpoint"""
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        self.sock.settimeout(self.conn_tmo)
        self.sock.connect(endpoint)

    def send_data(self, data):
        """Send data to the remote endpoint"""
        self.sock.sendall(data)
        self.sock.close()

class VsockListener:
    """Server"""
    def __init__(self, vsockhandle, conn_backlog=128):
        self.vsockhandle = vsockhandle
        self.conn_backlog = conn_backlog

    def bind(self, port):
        """Bind and listen for connections on the specified port"""
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        self.sock.bind((socket.VMADDR_CID_ANY, port))
        self.sock.listen(self.conn_backlog)
        self.sock.setblocking(0)
        self.run = True

    def recv_data(self, enclave, port):
        """Receive data from a remote endpoint"""
        while self.run:
            try:
                (from_client, (remote_cid, remote_port)) = self.sock.accept()
                data = from_client.recv(1024).decode()
                if not data:
                    break
                print("RECEIVE: "+data)
                dataStr = data.split(",")
                if enclave:
                    if dataStr[1] == "SetCredential":
                        self.accessKey = dataStr[2]
                        self.secretKey = dataStr[3]
                        self.sessionKey = dataStr[4]
                        self.vsockhandle.request(dataStr[0],"1",False)
                    elif dataStr[1] == "Decrypt":
                        plaintext1 = self.decryptText(dataStr[2]);
                        plaintext2 = self.decryptText(dataStr[3]);
                        returnMsg = "Buyer1 Wins"
                        if int(plaintext2)>int(plaintext1):
                            returnMsg = "Buyer2 Wins"
                        print("RECEIVE: sending response from enclave: "+returnMsg)
                        self.vsockhandle.request(dataStr[0],returnMsg,False)
                else:
                    self.vsockhandle.response(dataStr[0],dataStr[1])
                from_client.close()
            except:
                time.sleep(0.5)

    def decryptText(self, data):
        proc = subprocess.Popen(
            [
                "/usr/src/app/kmstool_enclave_cli",
                "decrypt",
                "--region", region,
                "--proxy-port", "8000",
                "--aws-access-key-id", self.accessKey,
                "--aws-secret-access-key", self.secretKey,
                "--aws-session-token", self.sessionKey,
                "--ciphertext", data,
            ],
            stdout=subprocess.PIPE
        )

        plaintext = proc.communicate()[0].decode()
        # plaintext's format is `PLAINTEXT: XXXXXXX`, extract the value
        plaintext_content = plaintext.split(": ")[1]
        base64_bytes = plaintext_content.encode('ascii')
        message_bytes = base64.b64decode(base64_bytes)
        message = message_bytes.decode('ascii')
        return message

    def close(self):
        self.run = False

class socketMessage:
    def __init__(self,msgID,msg):
        self.msgID = msgID
        self.msg = msg

def parent_handler(args):
    global boto3
    global codecs
    global csv
    global pd
    import boto3
    import codecs
    import csv
    import pandas as pd

    VsockConnection = VsockHandler(args.cid,args.port,False)
    print("Starting VsockConnection")
    VsockConnection.start()
    buyer1data = []
    buyer2data = []
    resultdata = []
    s3client = boto3.client("s3")
    stsclient = boto3.client("sts")

    stsresponse = stsclient.assume_role(
        RoleArn=instanceRoleARN,
        RoleSessionName='EnclaveDecrypt'
    )

    setCredentialResult = VsockConnection.request(0,"SetCredential,"+stsresponse['Credentials']['AccessKeyId']+","+stsresponse['Credentials']['SecretAccessKey']+","+stsresponse['Credentials']['SessionToken'],True)

    if setCredentialResult == "1":
        data = s3client.get_object(Bucket=bucketBuyer1, Key="encrypted.csv")
        for row in csv.DictReader(codecs.getreader("utf-8")(data["Body"])):
            buyer1data.append(row['[].bid'])

        data2 = s3client.get_object(Bucket=bucketBuyer2, Key="encrypted.csv")
        for row in csv.DictReader(codecs.getreader("utf-8")(data2["Body"])):
            buyer2data.append(row['[].bid'])

        for i in range(len(buyer1data)):
            print("Property "+str(i))
            result = VsockConnection.request(0,"Decrypt,"+buyer1data[i] + "," + buyer2data[i],True)
            print("Result: "+result)
            resultdata.append(result)
        VsockConnection.close()
        output_df = pd.DataFrame(
            data={"Property": ["1", "2", "3"], "Result": resultdata},
            columns=["Property", "Result"],
        )

        with io.StringIO() as csv_buffer:
            output_df.to_csv(csv_buffer, index=False)

            response = s3client.put_object(
                Bucket=bucketBiddingService, Key="output.csv", Body=csv_buffer.getvalue()
            )

            status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")

            if status == 200:
                print(f"Successful S3 put_object response. Status - {status}")
            else:
                print(f"Unsuccessful S3 put_object response. Status - {status}")
    else:
        print("Could not set credentials in Enclave")

def enclave_handler(args):
    VsockConnection = VsockHandler(3,args.port,True)
    print("Starting VsockConnection")
    VsockConnection.start()

def main():
    parser = argparse.ArgumentParser(prog='vsock-poc')
    parser.add_argument("--version", action="version",
                        help="Prints version information.",
                        version='%(prog)s 0.1.0')
    subparsers = parser.add_subparsers(title="options")

    client_parser = subparsers.add_parser("parent", description="Parent",
                                          help="Connect to a given cid and port.")
    client_parser.add_argument("cid", type=int, help="The remote endpoint CID.")
    client_parser.add_argument("port", type=int, help="The remote endpoint port.")
    client_parser.set_defaults(func=parent_handler)

    server_parser = subparsers.add_parser("enclave", description="Enclave",
                                          help="Listen on a given port.")
    server_parser.add_argument("port", type=int, help="The local port to listen on.")
    server_parser.set_defaults(func=enclave_handler)

    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit(1)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
