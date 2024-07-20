package main

import (
  "encoding/json"
  "fmt"
  "io/ioutil"
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

func main () {

  var jwkFile = "./tmp.jwk"
  var jweFile = "./tmp.jwe"

  key, meta, _ := readKey(jwkFile)

  cipherBuf, _ := ioutil.ReadFile(jweFile)
  plainBuf, _ := decrypt(key, cipherBuf)
  ioutil.WriteFile("tmp.bin", plainBuf, 0640)
  ipfs, _ := meta["ipfs"].(map[string]interface{})
  cid, _ := ipfs["cid"].(string)
  fmt.Print(cid)
}
