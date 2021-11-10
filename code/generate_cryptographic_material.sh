if [ "$#" -ne 2 ]; then
  echo "Illegal number of parameters"
  exit
fi

PRIVATE_KEY_PATH=$1
CERT_PATH=$2

openssl genrsa -out $PRIVATE_KEY_PATH 2048
chmod 600 $PRIVATE_KEY_PATH
openssl req -new -key $PRIVATE_KEY_PATH -out $CERT_PATH
openssl x509 -req -days 365 -in $CERT_PATH -signkey $PRIVATE_KEY_PATH -out $CERT_PATH
