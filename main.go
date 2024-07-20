package main

import (
  "compress/gzip"
  "encoding/json"
  "fmt"
  "io"
  "io/ioutil"
  "os"
  "github.com/lestrrat-go/jwx/v2/jwe"
  "github.com/lestrrat-go/jwx/v2/jwk"
)

func readKey(keyFile string) (jwk.Key, map[string]interface{}, error) {
  keyBuf, _ := ioutil.ReadFile(keyFile)
  var meta map[string]interface{}
  if jsonErr := json.Unmarshal(keyBuf, &meta); jsonErr != nil {
    return nil, nil, jsonErr
  }
  key, keyErr := jwk.ParseKey(keyBuf)
  if keyErr != nil {
    return nil, meta, keyErr
  }
  return key, meta, nil
}

func decrypt(key jwk.Key, cipherBuf [] byte) ([]byte, error) {
  var rawkey interface{}
  if keyErr := key.Raw(&rawkey); keyErr != nil {
    return nil, keyErr
  }
  return jwe.Decrypt(cipherBuf, jwe.WithKey(key.Algorithm(), rawkey))
}

func decryptCompressed(key jwk.Key, cipherReader io.Reader) ([]byte, error) {
  gzipReader, gzipErr := gzip.NewReader(cipherReader)
  if gzipErr != nil {
    return nil, gzipErr
  }
  cipherBuf, readErr := ioutil.ReadAll(gzipReader)
  if readErr != nil {
    return nil, readErr
  }
  return decrypt(key, cipherBuf)
}

func main () {

  var jwkFile = "./tmp.jwk"
  var jweFile = "./tmp.jwe.gz"

  key, meta, _ := readKey(jwkFile)

  jweReader, _ := os.Open(jweFile)
  plainBuf, _ := decryptCompressed(key, jweReader)

  ioutil.WriteFile("tmp.bin", plainBuf, 0640)

  ipfs, _ := meta["ipfs"].(map[string]interface{})
  cid, _ := ipfs["cid"].(string)
  fmt.Printf("%s\n", cid)
}
