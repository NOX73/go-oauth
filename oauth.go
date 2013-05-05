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
)

type Credentials struct {
  oauth_consumer_key string
  oauth_nonce string
  oauth_signature string
  oauth_signature_method string
  oauth_timestamp int64
  oauth_token string
  oauth_version string

  oauth_consumer_secret string
  oauth_token_secret string
}

func NewCredentials(oauth_consumer_key, oauth_token, oauth_consumer_secret, oauth_token_secret string) *Credentials{
  c := Credentials{
    oauth_consumer_key: oauth_consumer_key, 
    oauth_token: oauth_token,
    oauth_version: "1.0",
    oauth_signature_method: "HMAC-SHA1",
    oauth_nonce: GenerateNonce(),
    oauth_timestamp: time.Now().UTC().Unix(),

    oauth_consumer_secret: oauth_consumer_secret,
    oauth_token_secret: oauth_token_secret,
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
  return r.credentials.oauth_signature
}

func NewRequest(method, url string, form_value FormValue, credentials *Credentials) (*Request, error) {

  parameter_string := GenerateParameterString(&url, form_value, credentials)
  signature_base_string := GenerateSignatureBaseString(&method, &url, parameter_string)
  signing_key := GenerateSigningKey(credentials)
  signature := GenerateSignature(signature_base_string, signing_key)

  credentials.oauth_signature = *signature

  request := new(Request)
  request.credentials = credentials

  return request, nil
}

func GenerateParameterString (str_url *string, form_value FormValue, credentials *Credentials) *string {
  p_url, _ := url.Parse(*str_url)
  v := p_url.Query()

  for key, val := range form_value {
    v.Add(key, val) 
  }

  v.Add("oauth_consumer_key", credentials.oauth_consumer_key) 
  v.Add("oauth_nonce", credentials.oauth_nonce) 
  v.Add("oauth_signature_method", credentials.oauth_signature_method) 
  v.Add("oauth_timestamp", strconv.FormatInt(credentials.oauth_timestamp, 10))
  v.Add("oauth_token", credentials.oauth_token) 
  v.Add("oauth_version", credentials.oauth_version) 

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

  buffer.WriteString(url.QueryEscape(c.oauth_consumer_secret))
  buffer.WriteString("&")
  buffer.WriteString(url.QueryEscape(c.oauth_token_secret))

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
