# CMPE 272 - HW #7 Security
## Group: Well, That’s a Name

•	Design and build a PKI infrastructure that includes Root CA, Signing CA, and TLS Certificate.

•	E.g., as described here: http Links to an external site.://pki-tutorial.readthedocs.io/en/latest/simple Links to an external site./Links to an external site.

•	Use the TLS certificate to install a web server, e.g. tomcat, https:// Links to an external site.tomcat.apache.org/tomcat-7.0-doc/ssl-howto.htmlLinks to an external site.

•	Document your progress and submit Word document including github reference to code, etc..

## Create Root CA
### 1.1	Create directories
To begin, use the command below to clone the repository into a new directory called 'wellthatsaname.'
git clone https://github.com/sumanagral/wellthatsaname
Use mkdir to create the required directories. The CA resources are stored in the ca directory, while CRLs are kept in the crl directory, and user certificates are kept in the certs directory.
mkdir -p ca/root-ca/private ca/root-ca/db crl certs
chmod 700 ca/root-ca/private
### 1.2	Create database
In order to use the openssl ca command, the database files must already be present on the system.
cp /dev/null ca/root-ca/db/root-ca.db
cp /dev/null ca/root-ca/db/root-ca.db.attr
echo 01 > ca/root-ca/db/root-ca.crt.srl
echo 01 > ca/root-ca/db/root-ca.crl.srl
### 1.3	Create CA request
We generate a private key and a certificate signing request (CSR) for the root certification authority by means of the openssl req -new command
. openssl req -new \
    -config etc/root-ca.conf \
    -out ca/root-ca.csr \
    -keyout ca/root-ca/private/root-ca.key
 ![image](https://user-images.githubusercontent.com/83566582/206138821-a8713ced-cced-45be-8eeb-47840e7653af.png)

### 1.4	Create CA certificate
We generate a root CA certificate based on the CSR by using the openssl ca command. The root certificate is one that has been signed by itself, and it acts as the foundation upon which all other trust relationships in the PKI are built. The [ca] section of the configuration file is where the openssl ca command obtains its settings to configure itself.
openssl ca -selfsign \
    -config etc/root-ca.conf \
    -in ca/root-ca.csr \
    -out ca/root-ca.crt \
    -extensions root_ca_ext

 
 ![image](https://user-images.githubusercontent.com/83566582/206138888-25426ade-81e0-43da-a653-5a543a543d60.png)

 ![image](https://user-images.githubusercontent.com/83566582/206138930-9f226aad-32ae-4edd-bc8e-5e0efc9d2461.png)

## Create Signing CA
### 2.1 Create directories
The CA resources are stored in the ca directory, while CRLs are kept in the crl directory, and user certificates are kept in the certs directory.
mkdir -p ca/signing-ca/private ca/signing-ca/db crl certs
chmod 700 ca/signing-ca/private
### 2.2 Create database
cp /dev/null ca/signing-ca/db/signing-ca.db
cp /dev/null ca/signing-ca/db/signing-ca.db.attr
echo 01 > ca/signing-ca/db/signing-ca.crt.srl
echo 01 > ca/signing-ca/db/signing-ca.crl.srl
### 2.3 Create CA request
We generate a CSR and a private key for the signing CA by using the openssl req -new command. To safeguard the private key, we made use of a passphrase. The [req] section of the configuration file serves as the source for the configuration that is used by the openssl req command.
openssl req -new \
    -config etc/signing-ca.conf \
    -out ca/signing-ca.csr \
    -keyout ca/signing-ca/private/signing-ca.key
 ![image](https://user-images.githubusercontent.com/83566582/206139409-5345df2b-4acb-48e3-80db-2678e266916f.png)

### 2.4 Create CA certificate
Using the openssl ca command, a certificate is issued based on the CSR. The configuration of the command is read from the [ca] section of the configuration file. Note that the signing CA certificate is issued by the root CA.
openssl ca \
    -config etc/root-ca.conf \
    -in ca/signing-ca.csr \
    -out ca/signing-ca.crt \
    -extensions signing_ca_ext
 ![image](https://user-images.githubusercontent.com/83566582/206139578-d18992f3-de69-4285-a807-bd9b56f8624e.png)
![image](https://user-images.githubusercontent.com/83566582/206139601-b2c09c52-a39c-4beb-95b7-474d70468afa.png)

 
 
## Operate Signing CA
### 3.1 Create email request
Using the openssl req -new command, the private key and CSR for an email-security certificate are generated. We utilize a request configuration file prepared specifically for the task.
openssl req -new \
    -config etc/email.conf \
    -out certs/well.csr \
    -keyout certs/well.key
 ![image](https://user-images.githubusercontent.com/83566582/206139694-1ad5c100-1e14-4af3-b35b-7ce578dac095.png)

### 3.2 Create email certificate
We use the signing CA to issue the certificate for email protection. The extensions we attach define the certificate type. A copy of the certificate is stored as ca/signing-ca/01.pem in the certificate archive (01 being the certificate serial number in hex.)
openssl ca \
    -config etc/signing-ca.conf \
    -in certs/well.csr \
    -out certs/well.crt \
    -extensions email_ext
 ![image](https://user-images.githubusercontent.com/83566582/206143154-92431225-e7df-418e-b4e5-cd5bb2e2ad18.png)

### 3.3 Create TLS server request
Using another request configuration file, we then generate the private key and CSR for a TLS-server certificate.
SAN=DNS:www.awsdropbox.click \
openssl req -new \
    -config etc/server.conf \
    -out certs/ awsdropbox.click.csr \
    -keyout certs/ awsdropbox.click.key
 ![image](https://user-images.githubusercontent.com/83566582/206143187-982ea847-9cc2-4f9b-a23f-4497c8aec600.png)

### 3.4 Create TLS server certificate
The signing CA is utilized to issue the server certificate. The extensions we attach define the certificate type. A copy of the certificate is saved under the name ca/signing-ca/02.pem in the certificate archive.
openssl ca \
    -config etc/signing-ca.conf \
    -in certs/ awsdropbox.click csr \
    -out certs/ awsdropbox.click.crt \
    -extensions server_ext
 
 ![image](https://user-images.githubusercontent.com/83566582/206143225-a029ae55-321f-4be3-aa45-cffa9dbe226f.png)
![image](https://user-images.githubusercontent.com/83566582/206143275-02fb6c6c-e065-4ba2-9b91-2e9426f5ca35.png)
![image](https://user-images.githubusercontent.com/83566582/206143305-677ea1a7-e5a4-4cf7-b27d-085765600d09.png)

   
 
### 3.5 Revoke certificate
Certain events, such as the replacement of a certificate or the loss of a private key, necessitate that a certificate be revoked prior to its scheduled expiration date. In the CA database, the openssl ca -revoke command marks a certificate as revoked. It will be included in CRLs issued by the CA moving forward. The preceding instruction revokes the certificate with serial number 01 (hex).
openssl ca \
    -config etc/signing-ca.conf \
    -revoke ca/signing-ca/01.pem \
    -crl_reason superseded
![image](https://user-images.githubusercontent.com/83566582/206143341-3296fc62-f075-4c64-b6e2-5cd8d595d6d8.png)

 
### 3.6 Create CRL
The ca -gencrl command of openssl generates a certificate revocation list (CRL). The CRL contains all certificates from the CA database that have been revoked but have not yet expired. Every so often, a new CRL must be issued.
openssl ca -gencrl \
    -config etc/signing-ca.conf \
    -out crl/signing-ca.crl
 ![image](https://user-images.githubusercontent.com/83566582/206143406-014afe37-0e8c-4c8a-94ef-c9a6a1540891.png)


## Output Formats
### 4.1 Create DER certificate
All published certificates must be in DER format [RFC 2585#section-3].
openssl x509 \
    -in certs/well.crt \
    -out certs/well.cer \
    -outform der
### 4.2 Create DER CRL
All published CRLs must be in DER format [RFC 2585#section-3].
openssl crl \
    -in crl/signing-ca.crl \
    -out crl/signing-ca.crl \
    -outform der
### 4.3 Create PKCS#7 bundle
PKCS#7 is used to package multiple certificates. The format would also accommodate CRLs, but they are not utilized.
openssl crl2pkcs7 -nocrl \
    -certfile ca/signing-ca.crt \
    -certfile ca/root-ca.crt \
    -out ca/signing-ca-chain.p7c \
    -outform der
    ![image](https://user-images.githubusercontent.com/83566582/206143489-409d7a97-20a1-41c2-9cb0-fbd648248260.png)

    
### 4.5 Create PEM bundle
PKCS#12 is used to bundle a certificate and its private key.
openssl pkcs12 -export \
    -name "wellthatsaname" \
    -inkey certs/well.key \
    -in certs/well.crt \
    -out certs/well.p12
### 4.4 Create PKCS#12 bundle
PEM bundles are created by concatenating other PEM-formatted files. The most common forms are “cert chain”, “key + cert”, and “key + cert chain”.
cat ca/signing-ca.crt ca/root-ca.crt > \
    ca/signing-ca-chain.pem
cat certs/fred.key certs/well.crt > \
    certs/fred.pem
 ![image](https://user-images.githubusercontent.com/83566582/206143525-6a618e0e-02d6-4897-bacc-d2cf97e7f296.png)

## View Results
### View request
  
 ![image](https://user-images.githubusercontent.com/83566582/206143662-194b9a50-df13-478d-a75e-5355d015df30.png)
![image](https://user-images.githubusercontent.com/83566582/206143683-caa758f6-8d5d-40ab-b0ed-ab7ced651648.png)

### View certificate
  ![image](https://user-images.githubusercontent.com/83566582/206143717-c6b74d55-d8ec-4ffd-a819-5b8663684c52.png)
![image](https://user-images.githubusercontent.com/83566582/206143732-9751867f-538c-4314-9450-8d0c719fcf68.png)

 
### View CRL
   ![image](https://user-images.githubusercontent.com/83566582/206143762-d18cf7f1-a502-40a0-80d7-edfcfbde9990.png)
![image](https://user-images.githubusercontent.com/83566582/206143781-7e9c8e54-25cf-419c-b619-bee5f3e67952.png)

### View PKCS#7 bundle
    ![image](https://user-images.githubusercontent.com/83566582/206143797-8c79b78d-1e1b-43e2-a696-c8106f1ce45e.png)
![image](https://user-images.githubusercontent.com/83566582/206143821-c2eb473c-5b49-4dc9-8311-c5cc23674e4a.png)
![image](https://user-images.githubusercontent.com/83566582/206143837-d849eec7-a076-4dbe-a02b-d6161b753b16.png)
![image](https://user-images.githubusercontent.com/83566582/206143855-104fd7ee-c2b9-47f0-848c-0700004ff6f4.png)

 
### View PKCS#12 bundle
 
 ![image](https://user-images.githubusercontent.com/83566582/206143874-866dbd55-f67c-4146-8ebc-9a22e0a5079b.png)
![image](https://user-images.githubusercontent.com/83566582/206143892-4c78a10d-d037-42f4-8428-8e470622ed5b.png)
![image](https://user-images.githubusercontent.com/83566582/206143912-a8702936-7fcc-45bd-b51e-69f3e95a263e.png)

 
 

## Install Tomcat:
### Installed tomcat
![image](https://user-images.githubusercontent.com/83566582/206144025-24767fed-dcbe-417a-9939-731864049174.png)

 Generated a keystore and the certificate-key pair for the server and then imported the certificate-key pair to the 
Keystore:
 ![image](https://user-images.githubusercontent.com/83566582/206144043-82048700-4434-4e5e-8bdd-8b316399186d.png)
![image](https://user-images.githubusercontent.com/83566582/206144068-996fc4ff-5307-4ed9-84a8-15c961c89278.png)

Edited the server.xml file in the conf folder  
![image](https://user-images.githubusercontent.com/83566582/206144097-8bbc05ec-f090-483e-a943-df446f33a60b.png)
![image](https://user-images.githubusercontent.com/83566582/206144122-c736ddf2-90c1-4279-9b4d-69deaa3b2ac5.png)

![image](https://user-images.githubusercontent.com/83566582/206144150-2541bca4-87ee-43b6-b20c-bd31433e7700.png)

	
 
