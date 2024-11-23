import sys
import socket
import json
import pdb
import boto3
import base64
import click

#KMS_KEY1_ID='arn:aws:kms:us-east-1:992382448255:key/e5fb3ef4-0fa1-4ffe-9cd0-4824bc0f9b16'
KMS_KEY2_ID='arn:aws:kms:us-east-1:992382448255:key/696a9e9b-fdb3-4f34-802c-c98b99caa9e9'
REGION='us-east-1'

import sys
import socket
import requests
import json
import pdb

def get_aws_session_token():
    """
    Get the AWS credential from EC2 instance metadata
    """
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


def decrypt_data_key(kms_client, ciphertext_key):
    response=kms_client.decrypt(CiphertextBlob=ciphertext_key)
    return response

def create_conn_to_cid(cid):
    # Create a vsock socket object
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)

    # The port should match the server running in enclave
    port = 5000

    # Connect to the server
    s.connect((cid, port))

    return s

    # Send AWS credential to the server running in enclave
    s.send(str.encode(json.dumps(credential)))

    # receive data from the server
    print(s.recv(1024).decode())

    # close the connection 
    s.close()

def get_kms_client(access_key_id, secret_access_key, token):
    session = boto3.Session(region_name=REGION, aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key, aws_session_token=token)
    #return session.client('kms', endpoint_url=VSOCK_PROXY_URL, config=Config(proxies={'http': VSOCK_PROXY_URL}))
    pdb.set_trace()
    return session.client('kms')



@click.command()
@click.option('--config-file', required=True, type=click.Path(exists=True), help='Path to the configuration file.')
@click.option('--cid', required=True, type=str, help='Enclave CID.')
def main(config_file, cid):
    # Your main logic here
    click.echo(f'Config file: {config_file}')
    click.echo(f'CID: {cid}')


    # Read configuration 
    with open(config_file, "r") as f:
        config = json.load(f) 
    pdb.set_trace()

    # Get EC2 instance metedata
    pdb.set_trace()
    credentials = get_aws_session_token()

    #Construct params
    params = {'region': config['region'], 'credentials' : credentials, 'file_params' : config['file_params']}
    print(params)

    """
    #Decrypt Key test code
    kms_client = get_kms_client(credentials['access_key_id'], credentials['secret_access_key'], credentials['token'])
    ciphertext_key = sys.argv[1] 
    print(decrypt_data_key(kms_client, ciphertext_key))
    """

    #Enclave interaction
    #Get CID from command line parameter
    sock = create_conn_to_cid(int(cid))


    # Send AWS credential to the server running in enclave
    sock.send(str.encode(json.dumps(params)))
    
    # receive data from the server
    print(sock.recv(1024).decode())
    # close the connection 
    sock.close()


if __name__ == '__main__':
    main()
