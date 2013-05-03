package oauth

import(
  "math/rand"
)

type Credentials struct {
  oauth_consumer_key string
  oauth_nonce string
  oauth_signature string
  oauth_signature_method string
  oauth_timestamp int32
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
  }
  return &c
}

func GenerateNonce() string {
  var bytes [32]byte

  for i:=0;i!=32;i++ {
    bytes[i] = byte(rand.Int63n(122 - 48) + 48)
  }

  return string(bytes[:32])
}
