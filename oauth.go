package oauth

import(
  "math/rand"
  "time"
)

type Credentials struct {
  oauth_consumer_key string
  oauth_nonce string
  oauth_signature string
  oauth_signature_method string
  oauth_timestamp int64
  oauth_token string
  oauth_version string
}

func NewCredentials(oauth_consumer_key, oauth_token string) *Credentials{
  c := Credentials{
    oauth_consumer_key: oauth_consumer_key, 
    oauth_token: oauth_token,
    oauth_version: "1.0",
    oauth_signature_method: "HMAC-SHA1",
    oauth_nonce: GenerateNonce(),
    oauth_timestamp: time.Now().UTC().Unix(),
  }
  return &c
}

func GenerateNonce() string {
  var bytes [32]byte

  var b int64
  for i := 0; i != 32; i++ {
    b = rand.Int63n(62)
    switch {
    case b < 10:
      b += 48
    case b < 36:
      b += 55
    default:
      b += 61
    }
    bytes[i] = byte(b)
  }
                                                
  return string(bytes[:32])
}
