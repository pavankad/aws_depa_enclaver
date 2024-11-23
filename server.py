import boto3
import pdb
import subprocess
from botocore.config import Config
import base64
import logging
from cryptography.fernet import Fernet
#from aws_nitro_enclaves_sdk import Attestation
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os 
import socket
import json
from flask import Flask
from flask import render_template
from flask import request
from flask import jsonify
import requests
import base64


app = Flask(__name__)


# S3 and KMS configurations
VSOCK_PROXY_PORT = "8000"
KEY_SPEC = 'AES_256'
#ENC_CONTEXT = {'KeyId': 'cowin'}
KMS_KEY1_ID='arn:aws:kms:us-east-1:124355660528:key/3dd24190-639c-4994-bc59-370c8d1562cf'

def get_aws_session_token():
    #Get the AWS credential from EC2 instance metadata
    tok_headers = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
    r = requests.put("http://169.254.169.254/latest/api/token", headers=tok_headers)
    token = r.text
    headers = {"X-aws-ec2-metadata-token": token}
    r = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/", headers=headers)
    instance_profile_name = r.text
    print(f"Instance Profil name {instance_profile_name}")
    #instance_profile_name = 'KMS_instance'

    r = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/%s" % instance_profile_name, headers=headers)
    response = r.json()

    credentials = {
        'access_key_id' : response['AccessKeyId'],
        'secret_access_key' : response['SecretAccessKey'],
        'token' : response['Token']
    }
    return credentials

"""
def get_aws_session_token(token_code):

    client = boto3.client('sts')

    response = client.get_session_token(DurationSeconds=3600, SerialNumber="arn:aws:iam::992382448255:mfa/Pavan-macbook", TokenCode=token_code)
    cred = response['Credentials']
    credential = {
        'access_key_id' : cred['AccessKeyId'],
        'secret_access_key' : cred['SecretAccessKey'],
        'token' : cred['SessionToken']
    }
    print(credential)
    return credential

"""
def get_kms_client(region, access_key_id, secret_access_key, token):
    session = boto3.Session(region_name=region, aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key, aws_session_token=token)
    return session.client('kms')

def get_s3_client(region, access_key_id, secret_access_key, token):
    #return boto3.client('s3', endpoint_url=VSOCK_PROXY_URL, config=Config(proxies={'http': VSOCK_PROXY_URL}))
    # Create a Config object to specify the S3 endpoint URL
    session = boto3.Session(region_name=region, aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key, aws_session_token=token)
    return session.client('s3')

def decrypt_data_key_using_kms_cli(ciphertext_key, access_key_id, secret_access_key, token):
    """
    print(ciphertext_key)
    print(access_key_id)
    print(secret_access_key)
    print(token)
    proc = subprocess.Popen(
    [
        "/app/kmstool_enclave_cli",
        "genkey",
        "--region", "us-east-1",
        "--proxy-port", "8000",
        "--aws-access-key-id", access_key_id,
        "--aws-secret-access-key", secret_access_key,
        "--aws-session-token", token,
        "--key-id", "e5fb3ef4-0fa1-4ffe-9cd0-4824bc0f9b16",
        "--key-spec", "AES-256",
    ],
    stdout=subprocess.PIPE
    )

    result = proc.communicate()[0].decode()
    print(result)

    print("Here below ciphertext in b64........")
    ciphertext_b64 = result.split("\n")[0].split(":")[1].strip()
    plaintext_b64 = result.split("\n")[1].split(":")[1].strip()
    print(ciphertext_b64)
    print("Here below plaintext in b64....")
    print(plaintext_b64)
    """
    proc = subprocess.Popen(\
       [\
        "/app/kmstool_enclave_cli",\
        "decrypt",\
        "--region", "us-east-1",\
        "--proxy-port", "8000",\
        "--aws-access-key-id", access_key_id,\
        "--aws-secret-access-key", secret_access_key,\
        "--aws-session-token", token,\
        "--ciphertext", ciphertext_key,\
       ],\
       stdout=subprocess.PIPE\
    )

    result = proc.communicate()[0].decode()
    print("Here is the result ...")
    print(result)
    plaintext_b64 = result.split(":")[1].strip()
    return plaintext_b64
    """
    #TEST code
    proc = subprocess.Popen( [ "/app/a.out", ], stdout=subprocess.PIPE)

    result = proc.communicate()[0].decode()
    return result
    """

def decrypt_data(data_key_plaintext, ciphertext_data):
    f = Fernet(data_key_plaintext)
    file_contents_decrypted = f.decrypt(ciphertext_data)
    return file_contents_decrypted 

def read_file_from_s3(s3_client, bucket_name, file_key):
    response = s3_client.get_object(Bucket=bucket_name, Key=file_key)
    return response['Body'].read()

def write_file_to_s3(s3_client, bucket_name, file_key, data):
    s3_client.put_object(Bucket=bucket_name, Key=file_key, Body=data)


@app.route('/', methods=['GET'])
def hello():
    print("hello")
    return "hello", 200 

@app.route('/config', methods=['POST'])
def get_config():
    print("Starting server...")

    print("Here are params received>>>>>>>>")
    params = request.get_json() 
    print(params)
    region = params['region']
    file_params = params['file_params']
    credentials = get_aws_session_token()

    for file in file_params:
        s3_bucket = file['s3_bucket']
        filename = file['filename']
        data_key = file['data_key']

        try:
            # Produce attestion and get data key from KMS 
            kms_client = get_kms_client(region, credentials['access_key_id'], credentials['secret_access_key'], credentials['token'])
            response = kms_client.decrypt(KeyId=KMS_KEY1_ID, CiphertextBlob=base64.b64decode(data_key))
            plain_text = base64.b64encode(response['Plaintext'])
            response = {'key':plain_text}
            print(response)
        except Exception as err: 
            print("Could not decrypt key")
            raise


        # Step 1: Read the encrypted file from S3
        try:
            # Retrieve the list of existing buckets
            """
            #ec2_client = boto3.client("ec2")
            paginator = ec2_client.get_paginator("describe_instance_types")
            for page in paginator.paginate(
                Filters=[
                    {
                        "Name": "processor-info.supported-architecture",
                        "Values": ["x86_64"],
                    },
                    {"Name": "instance-type", "Values": ["*.micro", "*.small"]},
                ]
            ):
                inst_types += page["InstanceTypes"]
                print(inst_types)

            #s3 = boto3.client('s3')
            #response = s3.list_objects(Bucket=s3_bucket)
            print(response)

            #print(region)
            """
            s3_client = get_s3_client(region, credentials['access_key_id'], credentials['secret_access_key'], credentials['token'])
            encrypted_data_from_s3 = read_file_from_s3(s3_client, s3_bucket, filename)
            #s3 = boto3.resource('s3')
            #obj = s3.Object(s3_bucket, filename)
            #encrypted_data_from_s3 = obj.get()['Body'].read()
            #url = 'http://www.google.com'
            #resp = requests.get(url)
            #print(resp.text) # Printing response


            
        except Exception as err: 
            print("Could not read file from S3")
            print(str(err))
            raise

        # Step 2: Decrypt the file data
        try:
            decrypted_data = decrypt_data(plain_text, encrypted_data_from_s3)
            print(decrypted_data[:1000])
            print(decrypted_data[-1000:])
        except Exception as err:
            print("could not decrypt S3 data")
            raise
    return jsonify({"result": "success"}), 200

if __name__ == '__main__':
    app.run(port=os.getenv('PORT', 8000))
