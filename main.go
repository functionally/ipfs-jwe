package main

import (
  "bufio"
  "compress/gzip"
  "context"
  "errors"
  "fmt"
  "io"
  "io/ioutil"
  "os"
  "github.com/ipfs/go-cid"
  "github.com/ipfs/boxo/files"
  "github.com/ipfs/boxo/path"
  "github.com/ipfs/kubo/client/rpc"
  "github.com/lestrrat-go/jwx/v2/jwe"
  "github.com/lestrrat-go/jwx/v2/jwk"
  ma "github.com/multiformats/go-multiaddr"
)

func readKey(keyFile string) (jwk.Key, error) {
  keyBuf, _ := ioutil.ReadFile(keyFile)
  key, keyErr := jwk.ParseKey(keyBuf)
  if keyErr != nil {
    return nil, keyErr
  }
  return key, nil
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

func getCid(ctx context.Context, key jwk.Key) (*cid.Cid, error) {
  meta, metaErr := key.AsMap(ctx)
  if metaErr != nil {
    return nil, metaErr
  }
  ipfs, ipfsExists := meta["ipfs"].(map[string]interface{})
  if !ipfsExists {
    return nil, errors.New("Metadata key `ipfs` not found.")
  }
  cidString, cidExists := ipfs["cid"].(string)
  if !cidExists {
    return nil, errors.New("Metadata key `ipfs.cid` not found.")
  }
  cid, cidErr := cid.Decode(cidString)
  if cidErr != nil {
    return nil, cidErr
  }
  return &cid, nil
}

func getMime(ctx context.Context, key jwk.Key) (*string, error) {
  meta, metaErr := key.AsMap(ctx)
  if metaErr != nil {
    return nil, metaErr
  }
  mime, mimeExists := meta["mime"].(string)
  if !mimeExists {
    return nil, errors.New("Metadata key `mime` not found.")
  }
  return &mime, nil
}

func fetchCid(ctx context.Context, node *rpc.HttpApi, cid cid.Cid) (io.Reader, error) {
  path := path.FromCid(cid)
  file, ipfsErr := node.Unixfs().Get(ctx, path)
  if ipfsErr != nil {
    return nil, ipfsErr
  }
  reader, fileExists := file.(files.File)
  if !fileExists {
    return nil, errors.New("Not a `files.File`.")
  }
  return reader, nil
}

func fetchCompressedEncrypted(ctx context.Context, node *rpc.HttpApi, key jwk.Key) ([]byte, error) {
  theCid, cidErr := getCid(ctx, key)
  if cidErr != nil {
    return nil, cidErr
  }
  jweReader, fetchErr := fetchCid(ctx, node, *theCid)
  if fetchErr != nil {
    return nil, fetchErr
  }
  return decryptCompressed(key, jweReader)
}

func geminiError(code int, err error) []byte {
  status := fmt.Sprintf("%d %s\r\n", code, err.Error())
  return []byte(status)
}

func handleGemini(ctx context.Context, node *rpc.HttpApi, keys map[string]jwk.Key, kid string) []byte {

  key, keyErr := keys[kid]
  if !keyErr {
    return geminiError(51, errors.New("Key `" + kid + "` not found."))
  }

  mime, mimeErr := getMime(ctx, key)
  if mimeErr != nil {
    return geminiError(42, mimeErr)
  }

  plainBuf, fetchErr := fetchCompressedEncrypted(ctx, node, key)
  if fetchErr != nil {
    return geminiError(42, fetchErr)
  }

  status := fmt.Sprintf("%d %s\r\n\r\n", 20, *mime)
  return append([]byte(status), plainBuf...)
}

func connectIpfs(api string) (*rpc.HttpApi, error) {
  addr, addrErr := ma.NewMultiaddr(api)
    if addrErr != nil {
        return nil, addrErr
    }
  return rpc.NewApi(addr)
}

func readKeys(keysFile string) (map[string]jwk.Key, error) {

  handle, openErr := os.Open(keysFile)
  if openErr != nil {
    return nil, openErr
  }
  defer handle.Close()

  keys := make(map[string]jwk.Key)
  scanner := bufio.NewScanner(handle)
  for scanner.Scan() {
    line := scanner.Bytes()
    key, keyErr := jwk.ParseKey(line)
    if keyErr != nil {
      return nil, keyErr
    }
    keys[key.KeyID()] = key
  }

  return keys, nil
}

func cgiGemini(keysFile string, api string) {

  keys, keysErr := readKeys("./tmp.keys")
  if keysErr != nil {
    os.Stdout.Write(geminiError(42, errors.New("Failed reading keys file.")))
    return
  }

  ctx := context.Background()
  node, connectErr := connectIpfs(api)
  if connectErr != nil {
    os.Stdout.Write(geminiError(42, errors.New("Filed to connect to IPFS.")))
    return
  }

  kid := os.Getenv("PATH_INFO")
  if kid == "" {
    os.Stdout.Write(geminiError(59, errors.New("Missing key.")))
    return
  } else {
    response := handleGemini(ctx, node, keys, kid)
    _, writeErr := os.Stdout.Write(response)
    if writeErr != nil {
      os.Stdout.Write(geminiError(42, writeErr))
      return
    }
  }

}

func main() {
  cgiGemini("./tmp/keys", "/ip4/192.168.0.9/tcp/5001")
}
