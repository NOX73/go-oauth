package oauth

import (
  . "launchpad.net/gocheck"
  "testing"
  //"net/http"
  //"fmt"
  //"os"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }
type OAuthSuite struct{
  credentials *Credentials
  method string
  url string
  form_value FormValue
}
var _ = Suite(&OAuthSuite{})

func (s *OAuthSuite) SetUpTest(c *C) {
  s.credentials = NewCredentials("xvz1evFS4wEEPTGEFPHBog",
    "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb",
    "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw", 
    "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE")
  s.credentials.OauthTimestamp = 1318622958
  s.credentials.OauthNonce = "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg"

  s.method = "POST"
  s.url = "https://api.twitter.com/1/statuses/update.json?include_entities=true"
  s.form_value = make(FormValue)
  s.form_value["status"] = "Hello Ladies + Gentlemen, a signed OAuth request!"
}

func (s *OAuthSuite) TestGenerateNonce(c *C) {
  nonce := GenerateNonce()

  c.Assert(len(nonce), Equals, 32)
}

func (s *OAuthSuite) TestNewCredentials(c *C) {
  oauth_consumer_key := "oauth_consumer_key"
  oauth_token := "oauth_token"
  oauth_consumer_secret := "oauth_consumer_secret"
  oauth_token_secret := "oauth_token_secret"
  credentials := NewCredentials(oauth_consumer_key, oauth_token, oauth_consumer_secret, oauth_token_secret)
  
  c.Assert(credentials.OauthConsumerKey, Equals, oauth_consumer_key)
  c.Assert(credentials.OauthToken, Equals, oauth_token)
  c.Assert(credentials.OauthConsumerSecret, Equals, oauth_consumer_secret)
  c.Assert(credentials.OauthTokenSecret, Equals, oauth_token_secret)
  c.Assert(credentials.OauthSignatureMethod, Equals, "HMAC-SHA1")
  c.Assert(credentials.OauthVersion, Equals, "1.0")
  c.Assert(credentials.OauthNonce, Not(Equals), "")
  c.Assert(credentials.OauthTimestamp, Not(Equals), 0)
}

func (s *OAuthSuite) TestGenerateSignature(c *C) {


  parameter_string := GenerateParameterString(&s.url, s.form_value, s.credentials)
  c.Assert(*parameter_string, Equals, "include_entities=true&oauth_consumer_key=xvz1evFS4wEEPTGEFPHBog&oauth_nonce=kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1318622958&oauth_token=370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb&oauth_version=1.0&status=Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21")

  signature_base_string := GenerateSignatureBaseString(&s.method, &s.url, parameter_string)
  c.Assert(*signature_base_string, Equals, "POST&https%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521")

  signing_key := GenerateSigningKey(s.credentials)
  c.Assert(*signing_key, Equals, "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE")


  signature := GenerateSignature(signature_base_string, signing_key)
  c.Assert(*signature, Equals, "tnnArxj06cWHq44gCs1OSKk/jLY=")
}

func (s *OAuthSuite) TestNewRequest(c *C) {
  request, _ := NewRequest(s.method, s.url, s.form_value, s.credentials)

  c.Assert(request.HttpRequest().Header.Get("Authorization"), Equals, `OAuth oauth_consumer_key="xvz1evFS4wEEPTGEFPHBog", oauth_nonce="kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg", oauth_signature="tnnArxj06cWHq44gCs1OSKk%2FjLY%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1318622958", oauth_token="370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb", oauth_version="1.0"` )

  c.Assert(request.HttpRequest().ContentLength, Equals, int64(62))
}

func (s *OAuthSuite) TestReal(c *C) {

  cr := NewCredentials("XjY7q0CYwRxSBzCpUeRDzQ",
    "214373359-jn77FNlrKEajR4Gpp9l5msb1KXCGXZ7QeJPtt5TF",
    "cuseCPmxY4taUEmouOhXIvR7MVSUWdRKjKHvHKgVvOk", 
    "tO5hW1ye3myBnT78DspVbTKWFgadvKeU1EOiV3o5Tg")
  cr.OauthTimestamp = 1371899669 
  cr.OauthNonce = "45cec5e082f5f4ac231352a49ffb535d"

  method := "POST"
  url := "https://stream.twitter.com/1.1/statuses/filter.json"
  form_value := make(FormValue)
  form_value["track"] = "golang"

  request, _ := NewRequest(method, url, form_value, cr)
  body := make([]byte, 12)
  _, _ = request.HttpRequest().Body.Read(body)

  //request.HttpRequest().Write(os.Stdout)

  c.Assert(request.HttpRequest().Header.Get("Authorization"), Equals, `OAuth oauth_consumer_key="XjY7q0CYwRxSBzCpUeRDzQ", oauth_nonce="45cec5e082f5f4ac231352a49ffb535d", oauth_signature="qbgNEYVbXFy1968bb%2BMW4WtpNbM%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1371899669", oauth_token="214373359-jn77FNlrKEajR4Gpp9l5msb1KXCGXZ7QeJPtt5TF", oauth_version="1.0"` )
  c.Assert(string(body), Equals, "track=golang")
}

func (s *OAuthSuite) TestFormEncodedTest(c *C) {
  request, _ := NewRequest(s.method, s.url, s.form_value, s.credentials)

  c.Assert(request.HttpRequest().Header.Get("Content-Type"), Equals, "application/x-www-form-urlencoded")
}
