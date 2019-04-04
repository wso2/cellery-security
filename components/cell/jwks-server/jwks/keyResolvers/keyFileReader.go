package keyResolvers

import (
	"io/ioutil"
	"log"
)

func GetFileBasedKeys() (JwksJson, []byte, []byte) {
	privateKeyStr, isErrorKey := ReadFile(KEY_FILE_PATH)
	certificateStr, isErrorCert := ReadFile(CERT_FILE_PATH)
	if (isErrorKey == false) && (isErrorCert == false) {
		log.Println("Key file read from /etc/certs.")
		return FileBasedKeyReolver(privateKeyStr, certificateStr), nil, nil
	}else{
		log.Println("Unable to read key files from /etc/certs. Started generating self signed keys.")
		return KeyGenerator()
	}
}

func GetGeneratedKeys() (JwksJson, []byte, []byte){
	return KeyGenerator()
}

func ReadFile(filepath string) (string, bool) {
	data, err := ioutil.ReadFile(filepath)
	isError := false
	if err != nil {
		isError = true
		log.Printf("No such file found in %s , %s.\n", filepath, err)
	}
	return string(data), isError
}

