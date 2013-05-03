package oauth

import (
  . "launchpad.net/gocheck"
  "testing"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type OAuthSuite struct{}
var _ = Suite(&OAuthSuite{})

func (s *OAuthSuite) TestGenerateNonce(c *C) {
  credentials := new(Credentials)
  nonce, err := credentials.Nonce()

  c.Assert(err, IsNil)
  c.Assert(len(nonce), Equals, 32)
}
