

#please ensure that the public key for the self signed certificate is uploaded in Azure

import os
import requests
import warnings

import base64
import json
import uuid
import msvcrt
import sys
#msgraph-sdk
#from msgraph.core import GraphClient
from msal import ConfidentialClientApplication
import pandas as pd

from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt

# Constants
certificateFile = "certificate.pem"
privateKeyFile = "private_key.pem"
certificateValidityDays = 365
clientID = '871aeedf-5856-4e0f-9678-0a77a4a3f130'
clientSecret = 'ZBz8Q~Sl6qFiDIgw1VhGNAxHDZNI2dotG44SuaA9'
tenantID = 'c767978a-d8ea-4f5e-b3d8-886b19eb3d4f'
authority = f'https://login.microsoftonline.com/{tenantID}'
scope = 'https://graph.microsoft.com/.default'
tokenEndpoint = f'https://login.microsoftonline.com/{tenantID}/oauth2/v2.0/token'

organizationEndpoint = 'https://graph.microsoft.com/v1.0/groups/'

warnings.filterwarnings("ignore", category=DeprecationWarning)

def loadCert():

    if os.path.exists(certificateFile):

        with open(certificateFile, "rb") as f:
            certificate = x509.load_pem_x509_certificate(f.read())

        if certificate.not_valid_after > datetime.utcnow():
            print("Using existing valid certificate.")
            return certificate
        else:
            print("Existing certificate expired. Generating a new one.")
    else:
        print("Certificate file not found. Generating a new certificate.")

    privateKey = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"Cloudable"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"qtconsultantscom.onmicrosoft.com"),
    ])

    certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        privateKey.public_key()).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.utcnow()).not_valid_after(
        datetime.utcnow() + timedelta(days=certificateValidityDays)).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"qtconsultantscom.onmicrosoft.com")]), critical=False
    ).sign(privateKey, hashes.SHA256())

    with open(privateKeyFile, "wb") as f:

        f.write(privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(certificateFile, "wb") as f:

        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    return certificate

def generateJwtToken(privateKey, certThumbprint):
    now = datetime.utcnow()
    expire = now + timedelta(minutes=2)
    payload = {
        "aud": tokenEndpoint,
        "exp": int(expire.timestamp()),
        "iss": clientID,
        "jti": str(uuid.uuid4()),
        "nbf": int(now.timestamp()),
        "sub": clientID
    }

    header = {
        "alg": "RS256",
        "typ": "JWT",
        "x5t": certThumbprint
    }

    token = jwt.encode(payload, privateKey, algorithm="RS256", headers=header)
    return token

def fetchAccessToken(jwtToken):
    body = {
        "client_id": clientID,
        "client_assertion": jwtToken,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "scope": scope,
        "grant_type": "client_credentials"
    }

    response = requests.post(tokenEndpoint, data=body)

    if response.status_code == 200:
        return response.json()['access_token']
    else:
        print(f"Error: {response.status_code} - {response.text}")
        sys.exit("Failed to obtain access token.")

def fetchResource(accessToken):
    headers = {
        'Authorization': f'Bearer {accessToken}',
        'Content-Type': 'application/json'
    }

    response = requests.get(organizationEndpoint, headers=headers)
    return response

def getCertThumbprint(certificate):
    # Get the thumbprint (hash) of the certificate
    thumbprint = certificate.fingerprint(hashes.SHA1())
    thumbprint_base64 = base64.urlsafe_b64encode(thumbprint).decode('utf-8').rstrip('=')

    return thumbprint_base64

def main():
    certificate = loadCert()
    pubKey = certificate.public_key()
    pem = pubKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print("Public Key Details:")
    print(pem.decode())
    print("Please take a moment to ensure that the key listed above is uploaded into Azure before continuing.")

    print("Press any key to continue...")
    msvcrt.getch()

    with open(privateKeyFile, "rb") as f:
        privateKey = serialization.load_pem_private_key(f.read(), password=None)

    certThumbprint = getCertThumbprint(certificate)
    jwtToken = generateJwtToken(privateKey, certThumbprint)
    accessToken = fetchAccessToken(jwtToken)
    #tenantData = []
    response = fetchResource(accessToken)
    
    if response.status_code != 200:
        print(f'Error: {response.status_code} - {response.text}')
        sys.exit('Bad Response Please Try Again...')

    #print(result)
    #tenantData = response.json().get('value', [])
    #print(tenantData)

if __name__ == "__main__":
    main()