package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"github.com/ipfs/boxo/files"
	"github.com/ipfs/boxo/path"
	"github.com/ipfs/go-cid"
	"github.com/ipfs/kubo/client/rpc"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/urfave/cli/v2"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

func readKey(keyFile string) (jwk.Key, error) {
	var keyBuf, _ = ioutil.ReadFile(keyFile)
	var key, keyErr = jwk.ParseKey(keyBuf)
	if keyErr != nil {
		return nil, keyErr
	}
	return key, nil
}

func decrypt(key jwk.Key, cipherBuf []byte) ([]byte, error) {
	var rawkey interface{}
	if keyErr := key.Raw(&rawkey); keyErr != nil {
		return nil, keyErr
	}
	return jwe.Decrypt(cipherBuf, jwe.WithKey(key.Algorithm(), rawkey))
}

func decryptCompressed(key jwk.Key, cipherReader io.Reader) ([]byte, error) {
	var gzipReader, gzipErr = gzip.NewReader(cipherReader)
	if gzipErr != nil {
		return nil, gzipErr
	}
	var cipherBuf, readErr = ioutil.ReadAll(gzipReader)
	if readErr != nil {
		return nil, readErr
	}
	return decrypt(key, cipherBuf)
}

func getCid(ctx context.Context, key jwk.Key) (*cid.Cid, error) {
	var meta, metaErr = key.AsMap(ctx)
	if metaErr != nil {
		return nil, metaErr
	}
	var ipfs, ipfsExists = meta["ipfs"].(map[string]interface{})
	if !ipfsExists {
		return nil, errors.New("Metadata key `ipfs` not found.")
	}
	var cidString, cidExists = ipfs["cid"].(string)
	if !cidExists {
		return nil, errors.New("Metadata key `ipfs.cid` not found.")
	}
	var cid, cidErr = cid.Decode(cidString)
	if cidErr != nil {
		return nil, cidErr
	}
	return &cid, nil
}

func getMime(ctx context.Context, key jwk.Key) (*string, error) {
	var meta, metaErr = key.AsMap(ctx)
	if metaErr != nil {
		return nil, metaErr
	}
	var mime, mimeExists = meta["mime"].(string)
	if !mimeExists {
		return nil, errors.New("Metadata key `mime` not found.")
	}
	return &mime, nil
}

func fetchCid(ctx context.Context, node *rpc.HttpApi, cid cid.Cid) (io.Reader, error) {
	var path = path.FromCid(cid)
	var file, ipfsErr = node.Unixfs().Get(ctx, path)
	if ipfsErr != nil {
		return nil, ipfsErr
	}
	var reader, fileExists = file.(files.File)
	if !fileExists {
		return nil, errors.New("Not a `files.File`.")
	}
	return reader, nil
}

func fetchCompressedEncrypted(ctx context.Context, node *rpc.HttpApi, key jwk.Key) ([]byte, error) {
	var cid, cidErr = getCid(ctx, key)
	if cidErr != nil {
		return nil, cidErr
	}
	var jweReader, fetchErr = fetchCid(ctx, node, *cid)
	if fetchErr != nil {
		return nil, fetchErr
	}
	return decryptCompressed(key, jweReader)
}

func geminiError(code int, err error) []byte {
	var status = fmt.Sprintf("%d %s\r\n", code, err.Error())
	return []byte(status)
}

func handleGemini(ctx context.Context, node *rpc.HttpApi, keys map[string]jwk.Key, kid string) []byte {

	var key, keyErr = keys[kid]
	if !keyErr {
		return geminiError(51, errors.New("Key `"+kid+"` not found."))
	}

	var mime, mimeErr = getMime(ctx, key)
	if mimeErr != nil {
		return geminiError(42, mimeErr)
	}

	var plainBuf, fetchErr = fetchCompressedEncrypted(ctx, node, key)
	if fetchErr != nil {
		return geminiError(42, fetchErr)
	}

	var status = fmt.Sprintf("%d %s\r\n", 20, *mime)
	return append([]byte(status), plainBuf...)
}

func connectIpfs(apiAddr string) (*rpc.HttpApi, error) {
	var addr, addrErr = ma.NewMultiaddr(apiAddr)
	if addrErr != nil {
		return nil, addrErr
	}
	return rpc.NewApi(addr)
}

func readKeys(keysFile string) (map[string]jwk.Key, error) {

	var handle, openErr = os.Open(keysFile)
	if openErr != nil {
		return nil, openErr
	}
	defer handle.Close()

	var keys = make(map[string]jwk.Key)
	var scanner = bufio.NewScanner(handle)
	const maxLineLength = 250 * 1024
	scanner.Buffer(make([]byte, 0, maxLineLength), maxLineLength)
	for scanner.Scan() {
		var line = scanner.Bytes()
		var key, keyErr = jwk.ParseKey(line)
		if keyErr != nil {
			return nil, keyErr
		}
		keys[key.KeyID()] = key
	}

	return keys, nil
}

func decode(key jwk.Key, apiAddr string, outFile string) error {
	var ctx = context.Background()
	var node, ipfsErr = connectIpfs(apiAddr)
	if ipfsErr != nil {
		return ipfsErr
	}
	var plainBuf, fetchErr = fetchCompressedEncrypted(ctx, node, key)
	if fetchErr != nil {
		return fetchErr
	}
	return ioutil.WriteFile(outFile, plainBuf, 0640)
}

func fetch(keysFile string, apiAddr string, kid string, outFile string) error {
	var keys, keysErr = readKeys(keysFile)
	if keysErr != nil {
		return keysErr
	}
	var key, keyErr = keys[kid]
	if !keyErr {
		return errors.New("Key `" + kid + "` not found.")
	}
	return decode(key, apiAddr, outFile)
}

func cgiGemini(keysFile string, apiAddr string) {

	var keys, keysErr = readKeys(keysFile)
	if keysErr != nil {
		os.Stdout.Write(geminiError(42, keysErr))
		return
	}

	var ctx = context.Background()
	var node, ipfsErr = connectIpfs(apiAddr)
	if ipfsErr != nil {
		os.Stdout.Write(geminiError(42, ipfsErr))
		return
	}

	var kid = os.Getenv("PATH_INFO")
	if kid == "" {
		os.Stdout.Write(geminiError(59, errors.New("Missing key.")))
		return
	} else {
		var response = handleGemini(ctx, node, keys, kid)
		var _, writeErr = os.Stdout.Write(response)
		if writeErr != nil {
			os.Stdout.Write(geminiError(42, writeErr))
			return
		}
	}

}

func parseSCGIHeaders(data []byte) map[string]string {
	var headers = make(map[string]string)
	var parts = bytes.Split(data, []byte{0})
	for i := 0; i < len(parts)-1; i += 2 {
		headers[string(parts[i])] = string(parts[i+1])
	}
	return headers
}

func handleScgiGemini(ctx context.Context, node *rpc.HttpApi, keys map[string]jwk.Key, conn net.Conn) {

	defer conn.Close()

	var reader = bufio.NewReader(conn)
	var lengthStr, requestErr = reader.ReadString(':')
	if requestErr != nil {
		log.Printf("Failed reading request length: %v", requestErr)
		conn.Write(geminiError(42, requestErr))
		return
	}
	var length, lengthErr = strconv.Atoi(strings.TrimSuffix(lengthStr, ":"))
	if lengthErr != nil {
		log.Printf("Failed parsing request length: %v", lengthErr)
		conn.Write(geminiError(42, lengthErr))
		return
	}
	var headerData = make([]byte, length)
	var _, headerErr = io.ReadFull(reader, headerData)
	if headerErr != nil {
		log.Printf("Failed reading request header data: %v", headerErr)
		conn.Write(geminiError(42, headerErr))
		return
	}
	var _, terminatorErr = reader.ReadByte()
	if terminatorErr != nil {
		log.Printf("Failed reading request header terminator: %v", terminatorErr)
		conn.Write(geminiError(42, terminatorErr))
		return
	}

	var headers = parseSCGIHeaders(headerData)

	var kid, kidExists = headers["PATH_INFO"]
	if !kidExists {
		log.Printf("Missing key: %s", kid)
		conn.Write(geminiError(59, errors.New("Missing key.")))
		return
	} else {
		log.Printf("Key requested: %s", kid)
		var response = handleGemini(ctx, node, keys, kid)
		var _, writeErr = conn.Write(response)
		if writeErr != nil {
			log.Printf("Failed writing response: %v", writeErr)
			conn.Write(geminiError(42, writeErr))
			return
		}
		conn.Close()
		log.Printf(". . . sent %d bytes.", len(response))
	}

}

func scgiGemini(keysFile string, apiAddr string, socketFile string) {

	var keys, keysErr = readKeys(keysFile)
	if keysErr != nil {
		log.Fatalf("Failed to read keys file: %v", keysErr)
		return
	}
	log.Printf("Read %d keys from `%s`.", len(keys), keysFile)

	var ctx = context.Background()
	var node, ipfsErr = connectIpfs(apiAddr)
	if ipfsErr != nil {
		log.Fatalf("Failed to connect to IPFS: %v", ipfsErr)
	}
	log.Printf("Connected to IPFS API at `%s`.", apiAddr)

	if _, socketMissing := os.Stat(socketFile); socketMissing == nil {
		os.Remove(socketFile)
	}
	var listener, listenErr = net.Listen("unix", socketFile)
	if listenErr != nil {
		log.Fatalf("Failed to listen on socket: %v", listenErr)
	}
	defer listener.Close()
	log.Printf("SCGI server listening on `%s`.", listener.Addr().String())

	for {
		var conn, acceptErr = listener.Accept()
		if acceptErr != nil {
			log.Printf("Failed to accept connection: %v", acceptErr)
			continue
		}
		go handleScgiGemini(ctx, node, keys, conn)
	}

}

func main() {

	var apiAddr string
	var keyFile string
	var keysFile string
	var kid string
	var outFile string
	var socketFile string

	app := &cli.App{
		Name:  "ipfs-jwe",
		Usage: "Decrypt IPFS JWE.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "ipfs-api",
				Value:       "/ip4/127.0.0.1/tcp/5001",
				Usage:       "Multi-address for IPFS API.",
				Destination: &apiAddr,
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "serve-csgi",
				Usage: "Serve CSGI",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "keys-file",
						Value:       "keys.jsonarray",
						Usage:       "Array of JSON JWK keys.",
						Destination: &keysFile,
					},
					&cli.StringFlag{
						Name:        "socket-file",
						Value:       "ipfs-jwe-scgi.socket",
						Usage:       "SCGI socket path",
						Destination: &socketFile,
					},
				},
				Action: func(*cli.Context) error {
					scgiGemini(keysFile, apiAddr, socketFile)
					return nil
				},
			},
			{
				Name:  "handle-sgi",
				Usage: "Process SGI",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "keys-file",
						Usage:       "Array of JSON JWK keys.",
						Destination: &keysFile,
					},
				},
				Action: func(*cli.Context) error {
					cgiGemini(keysFile, apiAddr)
					return nil
				},
			},
			{
				Name:  "fetch",
				Usage: "Fetch an encrypted IPFS document",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "keys-file",
						Usage:       "Array of JSON JWK keys.",
						Destination: &keysFile,
					},
					&cli.StringFlag{
						Name:        "kid",
						Usage:       "Key ID of document to be retrieved",
						Destination: &kid,
					},
					&cli.StringFlag{
						Name:        "out-file",
						Value:       "/dev/stdout",
						Usage:       "Path to the output file",
						Destination: &outFile,
					},
				},
				Action: func(*cli.Context) error {
					return fetch(keysFile, apiAddr, kid, outFile)
				},
			},
			{
				Name:  "decrypt",
				Usage: "Decrypt an encrypted IPFS document",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "key",
						Usage:       "JWK file",
						Destination: &keyFile,
					},
					&cli.StringFlag{
						Name:        "kid",
						Usage:       "Key ID of document to be retrieved",
						Destination: &kid,
					},
					&cli.StringFlag{
						Name:        "out-file",
						Value:       "/dev/stdout",
						Usage:       "Path to the output file",
						Destination: &outFile,
					},
				},
				Action: func(*cli.Context) error {
					var key, keyErr = readKey(keyFile)
					if keyErr != nil {
						log.Fatalf("%v", keyErr)
					}
					return decode(key, apiAddr, outFile)
				},
			},
		},
	}

	if appErr := app.Run(os.Args); appErr != nil {
		log.Fatalf("%v", appErr)
	}

}
