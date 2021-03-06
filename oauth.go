package oauth

import(
  "math/rand"
  "time"
  "net/http"
  "strings"
  "bytes"
  "net/url"
  "crypto/sha1"
  "crypto/hmac"
  "encoding/base64"
  "sort"
  "strconv"
  "fmt"
)

type Credentials struct {
  OauthConsumerKey string
  OauthNonce string
  OauthSignature string
  OauthSignatureMethod string
  OauthTimestamp int64
  OauthToken string
  OauthVersion string

  OauthConsumerSecret string
  OauthTokenSecret string
}

func NewCredentials(consumer_key, token, consumer_secret, token_secret string) *Credentials{
  c := Credentials{
    OauthConsumerKey: consumer_key, 
    OauthToken: token,
    OauthVersion: "1.0",
    OauthSignatureMethod: "HMAC-SHA1",
    OauthNonce: GenerateNonce(),
    OauthTimestamp: time.Now().UTC().Unix(),

    OauthConsumerSecret: consumer_secret,
    OauthTokenSecret: token_secret,
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

type FormValue map[string]string
type Request struct {
  request http.Request
  credentials *Credentials
}

func (r *Request) GetSignature() string {
  return r.credentials.OauthSignature
}

func (r *Request) HttpRequest() *http.Request {
  return &r.request
}

func NewRequest(method, url string, form_value FormValue, credentials *Credentials) (*Request, error) {

  parameter_string := GenerateParameterString(&url, form_value, credentials)
  signature_base_string := GenerateSignatureBaseString(&method, &url, parameter_string)
  signing_key := GenerateSigningKey(credentials)
  signature := GenerateSignature(signature_base_string, signing_key)

  credentials.OauthSignature = *signature

  request := new(Request)
  request.credentials = credentials
  r, error := GenerateHttpRequest(&method, &url, form_value, credentials)

  request.request = *r

  return request, error
}

func GenerateParameterString (str_url *string, form_value FormValue, credentials *Credentials) *string {
  p_url, _ := url.Parse(*str_url)
  v := p_url.Query()

  for key, val := range form_value {
    v.Add(key, val) 
  }

  v.Add("oauth_consumer_key", credentials.OauthConsumerKey) 
  v.Add("oauth_nonce", credentials.OauthNonce) 
  v.Add("oauth_signature_method", credentials.OauthSignatureMethod) 
  v.Add("oauth_timestamp", strconv.FormatInt(credentials.OauthTimestamp, 10))
  v.Add("oauth_token", credentials.OauthToken) 
  v.Add("oauth_version", credentials.OauthVersion) 

  form_keys := make([]string, len(v))

  i := 0
  for key, _ := range v {
    form_keys[i] = key
    i++
  }

  sort.Strings(form_keys)

  var buffer bytes.Buffer
  for _, key := range form_keys {

    if buffer.Len() > 0 {
      buffer.WriteString("&")
    }

    buffer.WriteString(url.QueryEscape(key))
    buffer.WriteString("=")
    buffer.WriteString(strings.Replace(url.QueryEscape(v[key][0]), "+", "%20", -1))

  }

  result := buffer.String()
  return &result
}

func GenerateSignatureBaseString (method, str_url, parameter_string *string) *string {
  var buffer bytes.Buffer

  buffer.WriteString(strings.ToUpper(*method))
  buffer.WriteString("&")

  p_url, _ := url.Parse(*str_url)
  var uri bytes.Buffer

    uri.WriteString(p_url.Scheme)
    uri.WriteString("://")
    uri.WriteString(p_url.Host)
    uri.WriteString(p_url.Path)

  buffer.WriteString(url.QueryEscape(uri.String()))
  buffer.WriteString("&")
  buffer.WriteString(url.QueryEscape(*parameter_string))
  result := buffer.String()

  return &result
}

func GenerateSigningKey (c *Credentials) *string {
  var buffer bytes.Buffer

  buffer.WriteString(url.QueryEscape(c.OauthConsumerSecret))
  buffer.WriteString("&")
  buffer.WriteString(url.QueryEscape(c.OauthTokenSecret))

  result := buffer.String()

  return &result
}

func GenerateSignature (signature_base_string, signing_key *string) *string{
  sha := sha1.New
  h := hmac.New(sha, []byte(*signing_key))
  h.Write([]byte(*signature_base_string))

  encoder := base64.StdEncoding
  result := encoder.EncodeToString(h.Sum(nil))

  return &result
}

func GenerateHttpRequest(method, str_url *string, form_value FormValue, credentials *Credentials) (*http.Request, error) {
  v := make(url.Values, len(form_value))

  for key, val := range form_value {
    v.Set(key, val)
  }

  r, error := http.NewRequest(*method, *str_url, strings.NewReader(v.Encode()))

  auth_header := fmt.Sprintf(`OAuth oauth_consumer_key="%s", oauth_nonce="%s", oauth_signature="%s", oauth_signature_method="%s", oauth_timestamp="%d", oauth_token="%s", oauth_version="%s"`, 
    credentials.OauthConsumerKey,
    credentials.OauthNonce,
    url.QueryEscape(credentials.OauthSignature),
    credentials.OauthSignatureMethod,
    credentials.OauthTimestamp,
    credentials.OauthToken,
    credentials.OauthVersion)

    r.Header.Add("Authorization", auth_header)
    if len(v) > 0 {
      r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
    }

  return r, error
}
