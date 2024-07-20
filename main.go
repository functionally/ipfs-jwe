package main

import (
  "compress/gzip"
  "context"
  "errors"
  "io"
  "io/ioutil"
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

func connectIpfs(api string) (*rpc.HttpApi, error) {
  addr, addrErr := ma.NewMultiaddr(api)
    if addrErr != nil {
        return nil, addrErr
    }
  return rpc.NewApi(addr)
}

func main () {

  var jwkFile = "./tmp.jwk"
  var binFile = ".tmp/bin"
  var api = "/ip4/192.168.0.9/tcp/5001"

  ctx := context.Background()
  node, connectErr := connectIpfs(api)
  if connectErr != nil {
      panic(connectErr)
  }

  key, keyErr := readKey(jwkFile)
  if keyErr != nil {
    panic(keyErr)
  }

  plainBuf, fetchErr := fetchCompressedEncrypted(ctx, node, key)
  if fetchErr != nil {
    panic(fetchErr)
  }

  ioutil.WriteFile(binFile, plainBuf, 0640)
}
