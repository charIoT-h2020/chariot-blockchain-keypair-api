package main

import (
  "fmt"
  "crypto/ecdsa"
  "crypto/sha256"
  "crypto/elliptic"
  "crypto/rand"
  "encoding/base64"
  "encoding/json"
  "reflect"
  "math/big"
  "errors"
  "strings"
  "strconv"
  "net/http"
)

// SupportedMethods - Supported API end-points
var SupportedMethods = []string { "generate", "sign", "verify" }

// RPCRequest - The structure of an RPC request
type RPCRequest struct {
    Version string `json:"jsonrpc"`
    ID uint32 `json:"id"`
    Method string `json:"method"`
    Params []string `json:"params"`
}

// RPCResponse - The structure of an RPC response
type RPCResponse struct {
    Version string `json:"jsonrpc"`
    ID uint32 `json:"id"`
    Result string `json:"result"`
}

func isSupported(a string, list []string) bool {
    for _, b := range list {
        if b == a {
            return true
        }
    }
    return false
}

func unpackParams(params []string) (string, string, string, string) {
    for len(params) < 4 {
      params = append(params, "")
    }
    return params[0], params[1], params[2], params[3]
}

func signBlockchainAction(params []string) (string, error) {
    randomGen := rand.Reader
    privateKey, blockchainAction, publicKey, _ := unpackParams(params)

    tempBytes, err := base64.StdEncoding.DecodeString(string(publicKey))

    if err != nil {
        return "", err
    }

    tempSlice := tempBytes[0:44]
    firstSlice := tempSlice[:]

    tempSlice = tempBytes[44:88]
    secondSlice := tempSlice[:]

    decodedFirst, err := base64.StdEncoding.DecodeString(string(firstSlice))

    if err != nil {
        return "", err
    }

    decodedSecond, err := base64.StdEncoding.DecodeString(string(secondSlice))

    if err != nil {
        return "", err
    }

    newX := new(big.Int)
    newY := new(big.Int)
    newX = newX.SetBytes(decodedFirst)
    newY = newY.SetBytes(decodedSecond)

    decodedPub := &ecdsa.PublicKey{Curve:elliptic.P256(), X:newX, Y:newY}

    newD := new(big.Int)
    tempBytes, err = base64.StdEncoding.DecodeString(string(privateKey))

    if err != nil {
        return "", err
    }

    newD = newD.SetBytes(tempBytes)

    decodedPriv := &ecdsa.PrivateKey{PublicKey:*decodedPub,D:newD}

    // Convert & Generate Signature
    hexHash := []byte(blockchainAction)
    r, s, _ := ecdsa.Sign(randomGen, decodedPriv, hexHash)

    if publicKey != "" {
        if !ecdsa.Verify(decodedPub, hexHash, r, s) {
            return "", errors.New("Signature verification failed, provided keypair public key does not match private key")
        }
    }

    // Encode signature values
    encodedR := base64.StdEncoding.EncodeToString(r.Bytes())
    encodedS := base64.StdEncoding.EncodeToString(s.Bytes())

    return fmt.Sprintf("-----BEGIN CHARIOT R SIGNATURE-----\n%s\n------END CHARIOT R SIGNATURE------\n-----BEGIN CHARIOT S SIGNATURE-----\n%s\n------END CHARIOT S SIGNATURE------", encodedR, encodedS), nil
}

func verifyBlockchainAction(params []string) (string, error) {
    publicKey, blockchainAction, encodedR, encodedS := unpackParams(params)

    // Decode First Layer
    fullSlice, err := base64.StdEncoding.DecodeString(publicKey)

    if err != nil {
        return "", err
    }

    // Split Layer into two 44 byte halves
    tempSlice := fullSlice[0:44]
    firstSlice := tempSlice[:]

    tempSlice = fullSlice[44:88]
    secondSlice := tempSlice[:]

    // Decode the Base64 encoded halves
    decodedFirst, err := base64.StdEncoding.DecodeString(string(firstSlice))

    if err != nil {
        return "", err
    }

    decodedSecond, err := base64.StdEncoding.DecodeString(string(secondSlice))

    if err != nil {
        return "", err
    }

    // Set them as variables for Struct initialization
    newX := new(big.Int)
    newY := new(big.Int)
    newX = newX.SetBytes(decodedFirst)
    newY = newY.SetBytes(decodedSecond)

    decodedPub := &ecdsa.PublicKey{Curve:elliptic.P256(), X:newX, Y:newY}

    // Convert item signed to raw bytes
    hexHash := []byte(blockchainAction)

    // Decode R
    decodedR, err := base64.StdEncoding.DecodeString(encodedR)

    if err != nil {
        return "", err
    }

    // Decode S
    decodedS, err := base64.StdEncoding.DecodeString(encodedS)

    if err != nil {
        return "", err
    }

    r := new(big.Int)
    s := new(big.Int)
    r = r.SetBytes(decodedR)
    s = s.SetBytes(decodedS)

    // Verify Signature
    return strconv.FormatBool(ecdsa.Verify(decodedPub, hexHash, r, s)), nil
}

func generateKeypair() (string, error) {
    randomGen := rand.Reader
    curve := elliptic.P256()

    // Generation of a Private Key
    priv, err := ecdsa.GenerateKey(curve, randomGen)

    if err != nil {
        return "", err
    }

    privEncoded := base64.StdEncoding.EncodeToString(priv.D.Bytes())

    // Verification that encoding was conducted correctly
    decodedPriv, err := base64.StdEncoding.DecodeString(privEncoded)

    if err != nil {
        return "", err
    }

    if priv.D != priv.D.SetBytes(decodedPriv) {
        return "", errors.New("Decoded Private Key value mis-match, failed to generate private key")
    }

    // Derivation of Public Key w/ Type Assertion
    pub := priv.Public().(*ecdsa.PublicKey)

    // Base64 Encoded Key Creation
    pubOne := base64.StdEncoding.EncodeToString(pub.X.Bytes())
    pubTwo := base64.StdEncoding.EncodeToString(pub.Y.Bytes())
    pubEncoded := base64.StdEncoding.EncodeToString([]byte(pubOne+pubTwo))

    // Check that encoding was done correctly (Ref to signature generation for process)
    fullSlice, err := base64.StdEncoding.DecodeString(pubEncoded)

    if err != nil {
        return "", err
    }

    tempSlice := fullSlice[0:44]
    firstSlice := tempSlice[:]

    tempSlice = fullSlice[44:88]
    secondSlice := tempSlice[:]

    decodedFirst, err := base64.StdEncoding.DecodeString(string(firstSlice))

    if err != nil {
        return "", err
    }

    decodedSecond, err := base64.StdEncoding.DecodeString(string(secondSlice))

    if err != nil {
        return "", err
    }

    newX := new(big.Int)
    newY := new(big.Int)

    decodedPub := &ecdsa.PublicKey{
      Curve: elliptic.P256(),
      X: newX.SetBytes(decodedFirst),
      Y: newY.SetBytes(decodedSecond)}

    if !reflect.DeepEqual(pub, decodedPub) {
        return "", errors.New("Decoded Public Key value mis-match, failed to generate public key")
    }

    // Conduct signature verification to ensure keypair functions correctly
    hash := sha256.Sum256([]byte("test"))
    hexHash := hash[:]
    r, s, _ := ecdsa.Sign(randomGen, priv, hexHash)
    if !ecdsa.Verify(pub, hexHash, r, s) {
        return "", errors.New("Test signature verification failed, keypair generated was corrupt")
    }

    return fmt.Sprintf("-----BEGIN CHARIOT PRIVATE KEY-----\n%s\n------END CHARIOT PRIVATE KEY------\n-----BEGIN CHARIOT PUBLIC KEY-----\n%s\n------END CHARIOT PUBLIC KEY------", privEncoded, pubEncoded), nil
}

func executeRPC(method string, params []string) (string, error) {
  switch method {
  case "generate":
    return generateKeypair()
  case "sign":
    return signBlockchainAction(params)
  default:
    return verifyBlockchainAction(params)
  }
}

func rpcHandler(w http.ResponseWriter, r *http.Request) {
    d := json.NewDecoder(r.Body)

    d.DisallowUnknownFields()

    var rpc RPCRequest

    err := d.Decode(&rpc)
    if err != nil {
        // bad JSON or unrecognized json field
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    if rpc.Version != "2.0" {
        http.Error(w, fmt.Sprintf("Wrong RPC version, expected 2.0 but got %s", rpc.Version), http.StatusBadRequest)
        return
    }

    if !isSupported(rpc.Method, SupportedMethods) {
        http.Error(w, fmt.Sprintf("Unsupported method, expected one of \"%s\" but got %s", strings.Join(SupportedMethods, "\", \""), rpc.Method), http.StatusBadRequest)
        return
    }

    if rpc.Method == "sign" && (len(rpc.Params) < 2 || 3 < len(rpc.Params)) {
        http.Error(w, fmt.Sprintf("Illegal parameters, expected 2 or 3 but got %d", len(rpc.Params)), http.StatusBadRequest)
        return
    } else if rpc.Method == "verify" && len(rpc.Params) != 4 {
        http.Error(w, fmt.Sprintf("Illegal parameters, expected 4 but got %d", len(rpc.Params)), http.StatusBadRequest)
        return
    }

    if d.More() {
        http.Error(w, "JSON Object contained extraneous data", http.StatusBadRequest)
        return
    }

    result, e := executeRPC(rpc.Method, rpc.Params)

    if e != nil {
        // Execution failed
        http.Error(w, e.Error(), http.StatusInternalServerError)
        return
    }

    response := &RPCResponse{
      Version: rpc.Version,
      ID: rpc.ID,
      Result: result}

    json.NewEncoder(w).Encode(response)
}

func handleRequests() {
    http.HandleFunc("/", rpcHandler)
    http.ListenAndServe(":8081", nil)
}

func main() {
    handleRequests()
}
