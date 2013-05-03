package oauth

import(
  "math/rand"
)

type Credentials struct {
}

func (c *Credentials) Nonce() (string, error) {
  var bytes [32]byte

  for i:=0;i!=32;i++ {
    bytes[i] = byte(rand.Int63n(122 - 48) + 48)
  }

  return string(bytes[:32]), nil 
}
