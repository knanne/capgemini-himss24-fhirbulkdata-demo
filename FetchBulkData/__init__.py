import os
import logging

import time
from datetime import timezone, datetime, timedelta
from calendar import timegm

import re
import uuid
from base64 import urlsafe_b64encode
import hashlib

import requests
import json
import ndjson

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm, SignatureAlgorithm
from azure.keyvault.certificates import CertificateClient
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
from azure.core.exceptions import ResourceNotFoundError

from fhir.resources.parameters import Parameters, ParametersParameter

app = func.FunctionApp()

def get_token_url(smart_url):
    logging.info(f'Getting token URL from smart url: {smart_url}')
    try:
        r = requests.get(smart_url)
        token_url = r.json()['token_endpoint']
        logging.info(f'Retreived token url as {token_url}')
    except Exception as e:
        raise Exception('Could not find token url')
    return token_url

def build_crypto_client(vault_name, certificate_name=None, key_name=None):
    logging.info('Authenticating Azure Key Vault')
    credential = DefaultAzureCredential()

    if certificate_name is not None and key_name is not None:
        raise Exception('  Found both a certificate_name and key_name. Please use one or the other, not both.')
    if certificate_name is not None:
        certificate_client = CertificateClient(vault_url=f"https://{vault_name}.vault.azure.net/", credential=credential)
        cert = certificate_client.get_certificate(certificate_name)
        key_id = cert.key_id
        logging.info('  Successfully retreived certificate from vault')
    elif key_name is not None:
        key_client = KeyClient(vault_url=f"https://{vault_name}.vault.azure.net/", credential=credential)
        key = key_client.get_key(key_name)
        key_id = key.id
        logging.info('  Successfully retreived key from vault')

    crypto_client = CryptographyClient(key_id, credential)

    logging.info('  Successfully built crypto client with certificate')
    return crypto_client

def sign_jwt(client_id, token_url, crypto_client, kid=''):
    logging.info('Creating and Signing JSON Web Token (JWT)')
    
    jwt_payload = {
        'sub': client_id
        ,'iss': client_id
        ,'aud': token_url
        ,'jti': str(uuid.uuid4())
        ,'exp': datetime.now(tz=timezone.utc) + timedelta(minutes=5)
    }

    jwt_header = {
          "alg": "RS384"
          ,"typ": "JWT"
          ,"kid": kid
    }
    
    # Convert expiration time to milliseconds
    jwt_payload['exp'] = timegm(jwt_payload['exp'].utctimetuple())
        
    # convert header and payload json to byte strings
    headerb = json.dumps(jwt_header, separators=(",", ":")).encode('utf-8')
    payloadb = json.dumps(jwt_payload, separators=(",", ":")).encode('utf-8')
    
    # URL safe base 64 encode header and payload
    b64_header = urlsafe_b64encode(headerb).replace(b"=", b"")
    b64_payload = urlsafe_b64encode(payloadb).replace(b"=", b"")
    
    # Combine header and payload as <header>.<payload>
    b64_hp = b'.'.join([b64_header, b64_payload])
    
    # hash header.payload w/ hashing alg (SHA384) that aligns w/ signing alg (RS384)
    digest = hashlib.sha384(b64_hp).digest()
    logging.info('  Successfully built JWT')
    
    # Use the AZ crypto client to sign the hashed data using signing alg (RS384)
    # returns the signature and the metadata required to verify it
    result = crypto_client.sign(SignatureAlgorithm.rs384, digest)
    logging.info('  Successfully signed JWT using certificate')
    signature = result.signature
    
    # URL safe base 64 encode the signature
    b64_sig = urlsafe_b64encode(signature).replace(b"=", b"")
    
    # Form final signed JWT by combining <b64 header>.<b64 payload>.<b64 signature>
    signed_jwt = b'.'.join([b64_hp, b64_sig]).decode('utf-8')
    
    logging.info('  Successfully built signed JWT')
    return signed_jwt

def get_secret_for_client(secret_name):
    logging.info('Looking for Secret key by name')
    try:
        return os.environ[secret_name]
    except KeyError:
        raise Exception(f'No environmental variable found named {secret_name}')

def get_access_token(token_url, **kwargs):
    logging.info('Getting Access Token')
    signed_jwt = kwargs.pop('signed_jwt',None)
    client_id = kwargs.pop('client_id',None)
    client_secret = kwargs.pop('client_secret',None)
    scope = kwargs.pop('scope','')

    if signed_jwt is not None and client_secret is not None:
        raise Exception('  Found both a signed_jwt and client_secret. Please use one or the other, not both.')
    elif signed_jwt is not None:
        logging.info('  Using Signed JWT')
        
        token_req_params = {
            'grant_type': 'client_credentials',
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': signed_jwt,
            'scope': scope
        }

        r_token = requests.post(token_url, token_req_params)
    elif client_secret is not None:
        logging.info('  Using Secret')

        if client_id is not None:
            auth = urlsafe_b64encode(f'{client_id}:{client_secret}'.encode('utf-8')).replace(b"=", b"").decode('utf-8')

            h = {
                'Authorization': f'Basic {auth}',
                'accept': 'application/json'
            }

            r_token = requests.post(token_url, headers=h)
        else:
            logging.info('  When providing a client_secret, please provide a client_id as well.')
            raise Exception('When providing a client_secret, please provide a client_id as well.')
    else:
        logging.info('  Need one of signed_jwt and client_secret.')
        raise Exception('Need one of signed_jwt and client_secret.')
    
    if r_token.ok:
        r_token_j = json.loads(r_token.content)
        
        expire_time = datetime.now() + timedelta(hours = int(r_token_j['expires_in'])/3600)
        access_token = r_token_j['access_token']
        
        logging.info(f"  Successfully retrieved access token, expires at {expire_time}")
        return access_token, expire_time
    else:
        try:
            message = r_token.text
        except:
            message = ''
        logging.info(f"  Failed to retreive access token, {r_token.status_code} "+message)
        raise Exception(f"Failed to retreive access token, {r_token.status_code} "+message)

def kickoff_export(kickoff_url, access_token):
    logging.info(f'Kicking off bulk FHIR request with: {kickoff_url}...')
    
    kickoffHeaders = {
        'Accept': 'application/fhir+json',
        'Prefer': 'respond-async',
        'Authorization': f'Bearer {access_token}'
    }

    r_kickoff = requests.get(kickoff_url, headers=kickoffHeaders)
    status_code = r_kickoff.status_code
    status_url = r_kickoff.headers['Content-Location']
    
    logging.info(f'  Successfully kicked off export, status url is: {status_url}')
    return status_code, status_url

def build_storage_client(storage_name):
    account_url = f'https://{storage_name}.blob.core.windows.net'
    logging.info(f'Connecting to Blob Storage Account: {account_url}')
    credential = DefaultAzureCredential()
    blob_service_client = BlobServiceClient(account_url, credential=credential)
    logging.info('  Successfully connected')
    return blob_service_client

def get_list_blobs(blob_service_client: BlobServiceClient, container_name):
    logging.info(f'Looking for blobs in container: {container_name}')
    container_client = blob_service_client.get_container_client(container=container_name)
    blob_list = container_client.list_blobs()
    return blob_list

def build_fhir_import_parameters(storage_client, container_name, blob_clients):
    logging.info('Building FHIR import parameters')
    import_param = Parameters.construct()
    pp_all = []
    
    # input format parameter object
    pp_input_format = ParametersParameter.construct()
    pp_input_format.name = 'inputFormat'
    pp_input_format.valueString = 'application/fhir+ndjson'
    pp_all.append(pp_input_format)
    
    for blob_client in blob_clients:
        # extract resource name from blob name (e.g. Patient from Patient-4aeccdd9-0a79-46e0-a7f2-640f0c376e28.json)
        resource_name = blob_client.blob_name.split('-')[0]
        blob_uri = blob_client.url
        
        # file type parameter object (type of FHIR resource)
        pp_type = ParametersParameter.construct()
        pp_type.name = 'type'
        pp_type.valueString = resource_name
        
        # file url parameter object
        pp_url = ParametersParameter.construct()
        pp_url.name = 'url'
        pp_url.valueUri = blob_uri
        
        # overall file input parameter object
        pp_input = ParametersParameter.construct()
        pp_input.name = 'input'
        pp_input.part = [pp_type, pp_url]
        pp_all.append(pp_input)
        logging.info(f'  Added {blob_uri} to FHIR import')

    import_param.parameter = pp_all
    import_body = json.loads(import_param.json())
    
    logging.info('Successfully build FHIR import body')
    return import_body

def get_fhir_server_access_token(fhir_server):
    logging.info(f'Getting access token for FHIR Server: {fhir_server}')
    credential = DefaultAzureCredential()
    capgemini_fhir_server_at = credential.get_token(f'{fhir_server}/.default')
    access_token = capgemini_fhir_server_at.token
    
    logging.info('Successfully retrieved access token')
    return access_token

def import_to_fhir(fhir_server, import_body, access_token):
    logging.info(f'Importing Data for FHIR Server, Making a POST to {fhir_server}/$import')    
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Prefer': 'respond-async',
        'Content-Type': 'application/fhir+json'
    }
    r_kickoff = requests.post(f'{fhir_server}/$import', headers=headers, json=import_body)
    if r_kickoff.ok:
        status_code = r_kickoff.status_code
        status_url = r_kickoff.headers['Content-Location']
        logging.info(f'  Successfully kicked off import, status url is: {status_url}')
        return status_code, status_url
    else:
        try:
            message = r_kickoff.text
        except:
            message = ''
        logging.info(f"  Failed to kick off import, {r_kickoff.status_code} "+message)
        raise Exception(f"Failed to kick off import, {r_kickoff.status_code} "+message)

def poll_status(status_code, status_url, access_token):
    logging.info(f'Checking status with: {status_url}...')
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Prefer': 'respond-async',
        'Accept': 'application/fhir+json'
    }

    i = 0
    while status_code != 200 or i > 600:
        r_status = requests.get(status_url, headers=headers)
        status_code = r_status.status_code
        if status_code == 200:
            break
        elif status_code == 202:
            try:
                logging.info(f'''Status: {status_code} - {r_status.headers['X-Progress']}''')
            except:
                logging.info(f'Status: {status_code}')
            logging.info('Sleeping 30s...')
            time.sleep(30)
            i+=30
        else:
            logging.info(f'Status: {status_code} {r_status.text}')
            raise Exception(f'Status: {status_code} {r_status.text}')
    
    if status_code == 200:
        logging.info(f'Status: {status_code} - Operation Complete')

        # ensures status content is retrieved if status_code
        # was 200 before while loop
        r_status = requests.get(status_url, headers=headers)

        if 'capgemini' in status_url:
            logging.info(r_status.json()['output'])
            logging.info(r_status.json()['error'])

        return status_code, r_status.content
    else:
        logging.info(f'Polling taking too long...')
        raise Exception(f'Polling taking too long...')

def get_data_export(data_url, access_token):
    logging.info(f'Fetching data from {data_url}')
    data_header = {
        'Authorization': f'Bearer {access_token}',
        'Accept': 'application/fhir+ndjson'
    }
    r_file = requests.get(data_url, headers=data_header)
    logging.info(f'Successfully retreived file')
    return r_file

def copy_blobs(storage_client, source_container, target_container, copy_blobs):
    logging.info(f'Copying Blobs from {source_container}/ to {target_container}/')
    for blob_client in copy_blobs:
        logging.info(f'{blob_client.blob_name}')
        source_blob_uri = storage_client.url+source_container+'/'+blob_client.blob_name
        target_blob_uri = storage_client.url+target_container+'/'+blob_client.blob_name
        target_blob = storage_client.get_blob_client(target_container, blob_client.blob_name)
        target_blob.start_copy_from_url(source_blob_uri)
        source_blob = storage_client.get_blob_client(source_container, blob_client.blob_name)
        source_blob.delete_blob()
        logging.info('  Successfully copied')
    return None

def upload_blob_stream(blob_service_client: BlobServiceClient, container_name: str, blob_name: str, input_stream):
    logging.info(f'Uploading {blob_name} to {container_name} ')
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
    blob_client.upload_blob(input_stream, blob_type="BlockBlob")
    return blob_client

def process_demo_data(server_url, resource_name, data_bytes):
    logging.info('Processing Data for Demo')
    ndjson = data_bytes.decode(encoding='utf-8').rstrip('\r\n').split('\n')

    epic_demo_patient_id = 'egqBHVfQlt4Bw3XGXoxVxHg3'
    cerner_demo_patient_id = '5123829'
    
    demo_patient_identifier = """{
        "system": "http://hl7.org/fhir/sid/us-mbi",
        "type": {"coding": [{"code": "MC",
        "display": "Patient's Medicare number",
        "extension": [{
            "url": "https://bluebutton.cms.gov/resources/codesystem/identifier-currency",
            "valueCoding": {
                "code": "current",
                 "display": "Current",
                 "system": "https://bluebutton.cms.gov/resources/codesystem/identifier-currency"
            }
        }],
        "system": "http://terminology.hl7.org/CodeSystem/v2-0203"}]},
        "value": "1S00E00AA27"
    }
    """
    demo_condition_code = """{
        "coding" : [
            {
                "system" : "http://hl7.org/fhir/sid/icd-10-cm",
                "code" : "E11.59",
                "display" : "Type 2 diabetes mellitus with other circulatory complications"
            }
        ],
        "text" : "Type 2 diabetes mellitus with other circulatory complications"
    }
    """
    demo_medication_codeableconcept = """ {
        "coding": [
          {
            "system": "http://www.nlm.nih.gov/research/umls/rxnorm",
            "code": "106892",
            "display": "insulin isophane, human 70 UNT/ML / insulin, regular, human 30 UNT/ML Injectable Suspension [Humulin]"
          }
        ]
    }
    """

    if 'epic' in server_url:
        logging.info('Updating EPIC Data')
        if resource_name == 'Patient':
            for i,resource in enumerate(ndjson):
                resource_json = json.loads(resource)
                # only update the demo patient (one with conditions and medications)
                if resource_json['id'] == epic_demo_patient_id:
                    logging.info(f"  Updating Patient Resource with ID: {resource_json['id']}")
                    resource_json['identifier'] = [json.loads(demo_patient_identifier)]
                    ndjson[i] =  json.dumps(resource_json)
        elif resource_name == 'Condition':
            # update all conditions (all but the demo patient's will be ignored)
            for i,resource in enumerate(ndjson):
                logging.info(f' {i}: Updating Condition Resource')
                resource_json = json.loads(resource)
                resource_json['code'] = json.loads(demo_condition_code)
                resource_json['recordedDate'] = '2019-09-04T11:10:27.000Z'
                ndjson[i] =  json.dumps(resource_json)
        elif resource_name == 'MedicationRequest':
            # update all medications (all but the demo patient's will be ignored)
            for i,resource in enumerate(ndjson):
                logging.info(f'  {i}: Updating MedicationRequest')
                resource_json = json.loads(resource)
                try:
                    del resource_json['medicationReference']
                except:
                    pass
                resource_json['medicationCodeableConcept'] = json.loads(demo_medication_codeableconcept)
                resource_json['authoredOn'] = '2019-09-04'
                ndjson[i] = json.dumps(resource_json)
    elif 'cerner' in server_url:
        logging.info('Updating Cerner Data')
        if resource_name == 'Patient':
            for i,resource in enumerate(ndjson):
                resource_json = json.loads(resource)
                # only update the demo patient (one with conditions and medications)
                if resource_json['id'] == cerner_demo_patient_id:
                    logging.info(f"  Updating Patient Resource with ID: {resource_json['id']}")
                    resource_json['identifier'] = [json.loads(demo_patient_identifier)]
                    ndjson[i] =  json.dumps(resource_json)
        elif resource_name == 'MedicationRequest':
            for i,resource in enumerate(ndjson):
                logging.info(f'  {i}: Updating MedicationRequest')
                resource_json = json.loads(resource)
                resource_json['authoredOn'] = '2019-10-25'
                ndjson[i] = json.dumps(resource_json)
    elif 'bcda' in server_url:
        ndjson_removed = []
        logging.info('Updating CMS Data')
        if resource_name == 'ExplanationOfBenefit':
            for i,resource in enumerate(ndjson):
                resource_json = json.loads(resource)

                # remove eobs that are not for demo patient
                if resource_json['patient']['reference'] != 'Patient/-10000000000027':
                    ndjson_removed.append(resource_json['id'])
                else:
                    for ct in resource_json['type']['coding']:
                        if ct['system'] == 'http://terminology.hl7.org/CodeSystem/claim-type':
                            claim_type = ct['code']
                    
                    # remove non pharmacy eobs
                    if claim_type != 'pharmacy':
                        ndjson_removed.append(resource_json['id]'])
                    else:
                        for item in resource_json['item']:
                            serviced_date = item['servicedDate']
                        
                        # remove eobs with a service date before 2019-09-01
                        if serviced_date < '2019-09-01':
                            ndjson_removed.append(resource_json['id'])
                        else:
                            logging.info(f'  {i}: Updating ExplanationOfBenefit')

                            # remove meta element so import won't fail on version conflicts
                            del resource_json['meta']

                            # update rx claims with name, if necessary, and rxnorm code
                            for item in resource_json['item']:
                                for code in item['productOrService']['coding']:
                                    if code['system'] == 'http://hl7.org/fhir/sid/ndc':
                                        logging.info(f'   {i}: Getting additional info from NIH...')
                                        rxinfo = get_rxinfo(code['code'])
                                        
                                        # remove eobs where rxnorm can't be found
                                        if rxinfo['rxnorm'] == '':
                                            ndjson_removed.append(resource_json['id'])
                                        else:
                                            if 'display' not in code.keys():
                                                # remove eobs without existing rx name and rx name can't
                                                # be looked up
                                                if rxinfo['name'] == '':
                                                    ndjson_removed.append(resource_json['id'])
                                                else:
                                                    code['display'] = rxinfo['name']
                                                                                        
                                            rx_norm_code = {'system': 'http://www.nlm.nih.gov/research/umls/rxnorm',
                                                            'code': rxinfo['rxnorm']}
                                            item['productOrService']['coding'].append(rx_norm_code)
                    
                ndjson[i] = json.dumps(resource_json)
            
            logging.info(f'{len(ndjson) - len(ndjson_removed)}/{len(ndjson)} EOBs will be loaded')
            ndjson = [j for j in ndjson if json.loads(j)['id'] not in ndjson_removed]

    data_bytes = '\n'.join(ndjson).encode()
    return data_bytes

def get_rxinfo(ndc):
    base_url = 'https://rxnav.nlm.nih.gov/REST/ndcstatus.json?ndc='
    req_url = f'{base_url}{ndc}'
    r = requests.get(req_url)
    body = json.loads(r.content)
    return {'name': body['ndcStatus']['conceptName'], 'rxnorm': body['ndcStatus']['rxcui']}


def main(req: func.HttpRequest, patientBlob: func.Out[str], encounterBlob: func.Out[str], conditionBlob: func.Out[str], medicationRequestBlob: func.Out[str], practitionerBlob: func.Out[str], organizationBlob: func.Out[str], explanationOfBenefitBlob: func.Out[str], coverageBlob: func.Out[str]) -> func.HttpResponse:
    logging.info('Python HTTP trigger function started')

    ### PROCESS HTTP PARAMETERS ###
    try:
        req_body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            f"ERROR: Please provide a valid JSON body",
            status_code=400
        )
    
    server_url = req_body.get('server-url',None)
    if server_url is None:
        logging.info('ERROR: Missing server_url in request body')
        return func.HttpResponse(f"ERROR: Missing server_url in request body",status_code=400)
    
    smart_url = req_body.get('smart-url',None)
    token_url = req_body.get('token-url',None)
    if smart_url is None and token_url is None:
        logging.info('ERROR: Must provide one of smart-url or token-url in request body')
        return func.HttpResponse(f"ERROR: Must provide one of smart-url or token-url in request body",status_code=400)
    
    client_id = req_body.get('client-id',None)
    if client_id is None:
        logging.info('ERROR: Missing client-id in request body')
        return func.HttpResponse(f"ERROR: Missing client-id in request body",status_code=400)
    
    group_id = req_body.get('group-id',None)
    if group_id is None:
        logging.info('ERROR: Missing group-id in request body')
        return func.HttpResponse(f"ERROR: Missing group-id in request body",status_code=400)
    
    secret_name = req_body.get('secret-name',None)
    if not secret_name is None:
        auth_method = 'secret'
    else:
        logging.info('No secret-name provided, assuming authentication via JWT')
        auth_method = 'jwt'
    
    since_date = req_body.get('since_date',None) # Must be in format YYYY-MM-DDThh:mm:ss.sss+zz:zz (e.g. 2015-02-07T13:28:17.239+02:00 or 2017-01-01T00:00:00Z)
    if since_date is None:
        kickoff_url = f'{server_url}/Group/{group_id}/$export'
    else:
        kickoff_url = f'{server_url}/Group/{group_id}/$export?_since={since_date}'
    
    jwt_method = req_body.get('jwt_method','key') # Can be one of (certificate, key)
    kid = req_body.get('kid','https://fhirbulkdatakeyvault.vault.azure.net/keys/CapgeminiHIMSS24DemoKey/de37d81fcca74fa49346865f45b8534b')
    scope = req_body.get('scope','system/Condition.read system/MedicationRequest.read system/Patient.read')

    try:
        storage_name = os.environ["storage_name"]
        storage_client = build_storage_client(storage_name)
        export_container_name = os.environ["export_container_name"]
        
        ### AUTHENTICATE VENDOR FHIR SERVER ###
        if smart_url is not None:
            token_url = get_token_url(smart_url)
        
        if auth_method == 'jwt':
            vault_name = os.environ["vault_name"]
            if jwt_method == 'certificate':
                certificate_name = os.environ["certificate_name"]
                crypto_client = build_crypto_client(vault_name, certificate_name=certificate_name)
            elif jwt_method == 'key':
                key_name = os.environ["key_name"]
                crypto_client = build_crypto_client(vault_name, key_name=key_name)
            signed_jwt = sign_jwt(client_id, token_url, crypto_client, kid=kid)
            access_token, expire_time = get_access_token(token_url, signed_jwt=signed_jwt, scope=scope)
        elif auth_method == 'secret':
            client_secret = get_secret_for_client(secret_name)
            access_token, expire_time = get_access_token(token_url, client_id=client_id, client_secret=client_secret, scope=scope)

        ### KICK OFF EXPORT FROM VENDOR FHIR SERVER ###
        status_code, status_url = kickoff_export(kickoff_url, access_token)
        status_code, status_content = poll_status(status_code, status_url, access_token)

        ### GET EXPORT FROM VENDOR FHIR SERVER ###
        blob_clients = []
        for r in json.loads(status_content)['output']:
            resource_type = r['type']
            
            logging.info(f'Attemping to get export for {resource_type}')
            data_url = r['url']
            r_file = get_data_export(data_url, access_token)
            
            data_bytes = r_file.content

            file_name = resource_type+'-'+client_id+'-'+str(uuid.uuid4())+'.json'
            
            ### PROCESS DATA FOR DEMO ###
            data_bytes = process_demo_data(server_url, resource_type, data_bytes)

            ### LOCAL ONLY - WRITE TO FILE ###
            #logging.info('Writing to Local Storage')
            #with open('data/'+file_name, 'wb') as f:
            #    f.write(data_bytes

            ### UPLOAD TO BLOB STORAGE ###
            blob_client = upload_blob_stream(storage_client, export_container_name, file_name, data_bytes)
            blob_clients.append(blob_client)
        
        # TODO: Change this to Polling
        logging.info('Waiting for Uploads to complete, sleeping 30s...')
        time.sleep(30)

        ### IMPORT INTO CAPGEMINI FHIR SERVER ###
        import_body = build_fhir_import_parameters(storage_client, export_container_name, blob_clients)

        capgemini_fhir_server = os.environ["capgemini_fhir_server"]
        access_token = get_fhir_server_access_token(capgemini_fhir_server)
        status_code, status_url = import_to_fhir(capgemini_fhir_server, import_body, access_token)
        status_code, status_content = poll_status(status_code, status_url, access_token)
        
        ### MOVE BLOBS ONCE UPLOADED ###
        import_container_name = os.environ["import_container_name"]
        copy_blobs(storage_client, export_container_name, import_container_name, blob_clients)

        return func.HttpResponse(
            f"SUCCESS: FHIR Bulk Export Complete",
            status_code=200
        )
    except Exception as e:
        return func.HttpResponse(
            f"{e}",
            status_code=500
        )