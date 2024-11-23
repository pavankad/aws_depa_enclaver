import sys
import socket
import json
import pdb
import boto3
import base64
from cryptography.fernet import Fernet

KMS_KEY1_ID='arn:aws:kms:us-east-1:124355660528:key/3dd24190-639c-4994-bc59-370c8d1562cf'
#KMS_KEY2_ID='arn:aws:kms:us-east-1:992382448255:key/696a9e9b-fdb3-4f34-802c-c98b99caa9e9'
REGION='us-east-1'

import sys
import socket
import requests
import json
import pdb

S3_BUCKET_NAME = 'enclave-pavan-test'
S3_ORIGINAL_FILE_KEY = 'data_files.py'
S3_ENCRYPTED_FILE_KEY = 'data_enc'
def get_aws_session_token():
    #Get the AWS credential from EC2 instance metadata
    tok_headers = {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}
    r = requests.put("http://169.254.169.254/latest/api/token", headers=tok_headers)
    token = r.text
    headers = {"X-aws-ec2-metadata-token": token}
    r = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/", headers=headers)
    instance_profile_name = r.text
    #instance_profile_name = 'KMS_instance'

    r = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/%s" % instance_profile_name, headers=headers)
    response = r.json()

    credential = {
        'access_key_id' : response['AccessKeyId'],
        'secret_access_key' : response['SecretAccessKey'],
        'token' : response['Token']
    }
    return credential
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

def create_data_key(kms_client, cmk_id, key_spec='AES_256'):
    """Generate a data key to use when encrypting and decrypting data

    :param cmk_id: KMS CMK ID or ARN under which to generate and encrypt the
    data key.
    :param key_spec: Length of the data encryption key. Supported values:
        'AES_128': Generate a 128-bit symmetric key
        'AES_256': Generate a 256-bit symmetric key
    :return Tuple(EncryptedDataKey, PlaintextDataKey) where:
        EncryptedDataKey: Encrypted CiphertextBlob data key as binary string
        PlaintextDataKey: Plaintext base64-encoded data key as binary string
    :return Tuple(None, None) if error
    """
    # Create data key
    try:
        #response = kms_client.generate_data_key(KeyId=cmk_id, KeySpec=key_spec, EncryptionContext=enc_context)
        response = kms_client.generate_data_key(KeyId=cmk_id, KeySpec=key_spec)
    except ClientError as e:
        logging.error(e)
        return None, None

    # Return the encrypted and plaintext data key
    return base64.b64encode(response['CiphertextBlob']), base64.b64encode(response['Plaintext'])

def decrypt_data_key(kms_client, ciphertext_key):
    response=kms_client.decrypt(CiphertextBlob=ciphertext_key)
    return response

def read_file_from_s3(s3_client, bucket_name, file_key):
    response = s3_client.get_object(Bucket=bucket_name, Key=file_key)
    return response['Body'].read()

def write_file_to_s3(s3_client, bucket_name, file_key, data):
    s3_client.put_object(Bucket=bucket_name, Key=file_key, Body=data)


def encrypt_data(data_key_plaintext, data):
    #cipher = Cipher(algorithms.AES(plaintext_key), modes.GCM(), backend=default_backend())
    #encryptor = cipher.encryptor()
    #ciphertext = encryptor.update(data) + encryptor.finalize()
    f = Fernet(data_key_plaintext)
    file_contents_encrypted = f.encrypt(data)
    return file_contents_encrypted


def get_kms_client(access_key_id, secret_access_key, token):
    session = boto3.Session(region_name=REGION, aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key, aws_session_token=token)
    #return session.client('kms', endpoint_url=VSOCK_PROXY_URL, config=Config(proxies={'http': VSOCK_PROXY_URL}))
    return session.client('kms')

def get_s3_client(access_key_id, secret_access_key, token):
    #return boto3.client('s3', endpoint_url=VSOCK_PROXY_URL, config=Config(proxies={'http': VSOCK_PROXY_URL}))
    session = boto3.Session(region_name=REGION, aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key, aws_session_token=token)
    return session.client('s3')


def main():

    # Get EC2 instance metedata
    #token = sys.argv[1]
    #credentials = get_aws_session_token(token)
    credentials = get_aws_session_token()

    pdb.set_trace()
    #Create Key
    kms_client = get_kms_client(credentials['access_key_id'], credentials['secret_access_key'], credentials['token'])
    ciphertext_key, plaintext_key = create_data_key(kms_client, KMS_KEY1_ID, key_spec='AES_256')
    print(ciphertext_key)
    print(plaintext_key)

    #Read the file from S3
    s3_client = get_s3_client(credentials['access_key_id'], credentials['secret_access_key'], credentials['token'])
    pdb.set_trace()
    original_data = read_file_from_s3(s3_client, S3_BUCKET_NAME, S3_ORIGINAL_FILE_KEY)


    # Encrypt the file data
    encrypted_data = encrypt_data(plaintext_key, original_data)

    # Write the encrypted file back to S3
    write_file_to_s3(s3_client, S3_BUCKET_NAME, S3_ENCRYPTED_FILE_KEY, encrypted_data)

    """
    #Decrypt Key
    kms_client = get_kms_client(credentials['access_key_id'], credentials['secret_access_key'], credentials['token'])
    print(decrypt_data_key(kms_client, base64.b64decode(ciphertext_key)))
    """


if __name__ == '__main__':
    main()
