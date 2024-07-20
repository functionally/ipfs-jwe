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
  if err := json.Unmarshal(keyBuf, &meta); err != nil {
    return nil, nil, err
  }
  key, err := jwk.ParseKey(keyBuf)
  if err != nil {
    return nil, meta, err
  }
  return key, meta, nil
}

func decrypt(key jwk.Key, cipherBuf [] byte) ([]byte, error) {
  var rawkey interface{}
  if err := key.Raw(&rawkey); err != nil {
    return nil, err
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

  h, _ := os.Open(jweFile)
  plainBuf, _ := decryptCompressed(key, h)
  ioutil.WriteFile("tmp.bin", plainBuf, 0640)
  ipfs, _ := meta["ipfs"].(map[string]interface{})
  cid, _ := ipfs["cid"].(string)
  fmt.Printf("%s\n", cid)
}
