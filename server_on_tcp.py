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

# S3 and KMS configurations
VSOCK_PROXY_PORT = "8000"
KEY_SPEC = 'AES_256'
#ENC_CONTEXT = {'KeyId': 'cowin'}

def get_kms_client(region, access_key_id, secret_access_key, token):
    session = boto3.Session(region_name=region, aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key, aws_session_token=token)
    #return session.client('kms', endpoint_url=VSOCK_PROXY_URL, config=Config(proxies={'http': VSOCK_PROXY_URL}))
    return session.client('kms')

def get_s3_client(region, access_key_id, secret_access_key, token):
    #return boto3.client('s3', endpoint_url=VSOCK_PROXY_URL, config=Config(proxies={'http': VSOCK_PROXY_URL}))
    # Create a Config object to specify the S3 endpoint URL
    config = Config(
        proxies={
            'http': "http://127.0.0.1:8001",
            'https': "http://127.0.0.1:8001" 
        }
    )
    session = boto3.Session(region_name=region, aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key, aws_session_token=token)
    return session.client('s3', config=config)

def decrypt_data_key_using_kms_cli(ciphertext_key, access_key_id, secret_access_key, token):
    print(ciphertext_key)
    print(access_key_id)
    print(secret_access_key)
    print(token)
    """
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
    TEST code
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

def connect_to_master():

    # Create a vsock socket object
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)

    # Listen for connection from any CID
    cid = socket.VMADDR_CID_ANY

    # The port should match the client running in parent EC2 instance
    port = 5000

    # Bind the socket to CID and port

    sock.bind((cid, port))

    # Listen for connection from client
    sock.listen()

    return sock


def main():
    print("Starting server...")

    #kms_client = get_kms_client()
    master_sock = connect_to_master()

    while True:
        conn, addr = master_sock.accept()

        print("received connection")
        # Get Configuration sent from parent instance
        payload = conn.recv(4096)
        params = json.loads(payload.decode())
        print("Here are params received>>>>>>>>")
        print(params)
        region = params['region']
        credentials = params['credentials']
        file_params = params['file_params']
        
        for file in file_params:
            s3_bucket = file['s3_bucket']
            filename = file['filename']
            data_key = file['data_key']

            # Produce attestion and get data key from KMS 
            plain_text = decrypt_data_key_using_kms_cli(data_key, credentials['access_key_id'], credentials['secret_access_key'], credentials['token'])
            response = {'key':plain_text}
            conn.send(str.encode(json.dumps(response)))

            # Step 1: Read the encrypted file from S3
            print(region)
            s3_client = get_s3_client(region, credentials['access_key_id'], credentials['secret_access_key'], credentials['token'])
            encrypted_data_from_s3 = read_file_from_s3(s3_client, s3_bucket, filename)

            # Step 2: Decrypt the file data
            decrypted_data = decrypt_data(plain_text, encrypted_data_from_s3)
            print(decrypted_data)
        conn.close()

if __name__ == '__main__':
    main()

