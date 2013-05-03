package oauth

import (
  . "launchpad.net/gocheck"
  "testing"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }
type OAuthSuite struct{
  credentials *Credentials
}
var _ = Suite(&OAuthSuite{})

func (s *OAuthSuite) SetUpTest(c *C) {
  s.credentials = new(Credentials)
}

func (s *OAuthSuite) TestGenerateNonce(c *C) {
  nonce := GenerateNonce()

  c.Assert(len(nonce), Equals, 32)
}


func (s *OAuthSuite) TestNewCredentials(c *C) {
  oauth_consumer_key := "oauth_consumer_key"
  oauth_token := "oauth_token"
  credentials := NewCredentials(oauth_consumer_key, oauth_token)
  
  c.Assert(credentials.oauth_consumer_key, Equals, oauth_consumer_key)
  c.Assert(credentials.oauth_token, Equals, oauth_token)
  c.Assert(credentials.oauth_signature_method, Equals, "HMAC-SHA1")
  c.Assert(credentials.oauth_version, Equals, "1.0")
  c.Assert(credentials.oauth_nonce, Not(Equals), "")
  c.Assert(credentials.oauth_timestamp, Not(Equals), 0)
}
 
