while getopts g:u:s: flag
do
    case "${flag}" in
        g) gen=${OPTARG};;
        u) user=${OPTARG};;
        s) subj=${OPTARG};;
    esac
done
if [ "$gen" = "crt" ]; then
        echo "************************************************************"
        echo "* Generate key pair in ./ca                                *"
        echo "* Upload public key - New-AAAUserAuthCert -CertFile ca.crt *"
        echo "************************************************************"
        mkdir ca
        cd ca
        openssl genrsa -des3 -out ca.key 4096              
        openssl req -new -x509 -days 10000 -key ca.key -out ca.crt
        mkdir ca.db.certs 
        touch ca.db.index
        echo 1234 > ca.db.serial
        cd ..
elif [ "$gen" = "pfx" -a -n "$user" ]; then
        echo "************************"
        echo "* Generate private key *"
        echo "* Login with $user.pfx *"
        echo "************************"
        echo "[ ca ] 
default_ca = ca_default 
[ ca_default ] 
dir = ./ca 
certs = \$dir 
new_certs_dir = \$dir/ca.db.certs 
database = \$dir/ca.db.index 
serial = \$dir/ca.db.serial 
RANDFILE = \$dir/ca.db.rand 
certificate = \$dir/ca.crt 
private_key = \$dir/ca.key 
default_days = 365 
default_crl_days = 30 
default_md = md5 
preserve = no 
policy = generic_policy 
[ generic_policy ] 
countryName = optional 
stateOrProvinceName = optional 
localityName = optional 
organizationName = optional 
organizationalUnitName = optional 
commonName = optional 
emailAddress = optional 
[req] 
x509_extensions = usr_cert 
req_extensions = v3_req 
[ usr_cert ] 
subjectAltName = @alt_names 
[ v3_req ] 
subjectAltName = @alt_names 
[alt_names] 
otherName=1.3.6.1.4.1.311.20.2.3;UTF8:$user" > $user-ca.conf
        echo "[req] 
x509_extensions = usr_cert 
req_extensions = v3_req 
distinguished_name = req_distinguished_name 
[req_distinguished_name] 
[ usr_cert ] 
subjectAltName = @alt_names 
[ v3_req ] 
subjectAltName = @alt_names 
[alt_names] 
otherName=1.3.6.1.4.1.311.20.2.3;UTF8:$user" > $user-san.conf
        if [ -z $subj ]; then
                subject="/CN=$user"
	else
		subject=$subj
        fi
	echo $subject
        openssl req -new -sha256 -config $user-san.conf -newkey rsa:4096 -nodes -keyout "$user-key.pem" -out "$user-req.pem" -subj "$subject"
        openssl ca -md sha256 -config $user-ca.conf -extensions v3_req -out "$user-certificate.pem.crt" -infiles "$user-req.pem" 
        openssl pkcs12 -inkey "$user-key.pem" -in "$user-certificate.pem.crt" -export -out "$user.pfx" 
        rm $user-ca.conf
        rm $user-san.conf
        rm $user-certificate.pem.crt
        rm $user-key.pem
        rm $user-req.pem
else
	echo "Usage:"
	echo "	ps> Set-AAAAutenMethod -CertAuth"
	echo "	./AAAUserAuthCert.sh -g crt"
	echo "	ps> New-AAAUserAuthCert -CertFile \".\\\\ca.cert\"" 
    	echo "	./AAAUserAuthCert.sh -g pfx -u hagrid@XXX.onmicrosoft.com -s \"/C=AU/ST=XX/L=XX/O=XXX/OU=IT/CN=hagrid@XXX.onmicrosoft.com\""
fi