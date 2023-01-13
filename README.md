# networking

## HTTPS

For accepting HTTPS request, you'll need OpenSSL libraries. You can install them via apt or download pre-compilated binaries for Windows [here](https://https://wiki.openssl.org/index.php/Binaries).)

For accepting HTTPS request, you'll need a certificate. To be specific, the following ones:

* server.crt
* server.key
* dh2048.pem

For generating self signed version of the certificate, you can run: 
(Stolen from [here](https://stackoverflow.com/questions/6452756/exception-running-boost-asio-ssl-example).)

```shell
openssl genrsa -des3 -out server.key 2048
openssl req -new -key server.key -out server.csr

*sample*
Country Name (2 letter code) [AU]:BR
State or Province Name (full name) [Some-State]:RJ
Locality Name (eg, city) []:Rio de Janeiro
Organization Name (eg, company) [Internet Widgits Pty Ltd]:Moonslate
Organizational Unit Name (eg, section) []:SomeUnitName
Common Name (e.g. server FQDN or YOUR name) []:localhost
Email Address []:.

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:.
An optional company name []:.

openssl x509 -req -days 3650 -in server.csr -signkey server.key -out server.crt
cp server.key server.key.secure
openssl rsa -in server.key.secure -out server.key
openssl dhparam -out dh2048.pem 2048
```
You can have then all in your resources folder, so uva will copy then to the build directory
