package jwt

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/lunny/tango"
)

var (
	Bearer        = "Bearer"
	DefaultKey    = "JWT"
)

type auther interface {
	SetClaims(map[string]interface{})
	GetClaim(string) interface{}
}

type Auther map[string]interface{}

func (a Auther) SetClaims(claims map[string]interface{}) {
	a = claims
}

func (a Auther) GetClaim(key string) interface{} {
	return a[key]
}

type Options struct {
	KeyFunc func(*tango.Context) (string, error)
	CheckWebSocket bool
}

func prepareOptions(opts []Options) Options {
	var opt Options
	if len(opts) > 0 {
		opt = opts[0]
	}
	if opt.KeyFunc == nil {
		opt.KeyFunc = func(ctx *tango.Context) (string, error) {
			return DefaultKey, nil
		}
	}

	return opt
}

// A JSON Web Token middleware
func New(opts ...Options) tango.HandlerFunc {
	opt := prepareOptions(opts)
	return func(ctx *tango.Context) {
		if !opt.CheckWebSocket {
			// Skip WebSocket
			if (ctx.Req().Header.Get("Upgrade")) == "WebSocket" {
				ctx.Next()
				return
			}
		}

		if a, ok := ctx.Action().(auther); ok {
			key, err := opt.KeyFunc(ctx)
			if err != nil {
				ctx.Result = err
				return
			}

			auth := ctx.Req().Header.Get("Authorization")
			l := len(Bearer)
			if len(auth) > l+1 && auth[:l] == Bearer {
				t, err := jwt.Parse(auth[l+1:], func(token *jwt.Token) (interface{}, error) {
					// Always check the signing method
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
					}

					// Return the key for validation
					return []byte(key), nil
				})

				if err == nil && t.Valid {
					// Store token claims
					a.SetClaims(t.Claims)
					ctx.Next()
					return
				}
			}

			ctx.Result = tango.Unauthorized()
			return
		}

		ctx.Next()
	}
}

func NewToken(key string, claims ...map[string]interface{}) (string, error) {
	// New web token.
	token := jwt.New(jwt.SigningMethodHS256)

	// Set a header and a claim
	token.Header["typ"] = "JWT"
	token.Claims["exp"] = time.Now().Add(time.Second * 60).Unix()

	if len(claims) > 0 {
		for k, v := range claims[0] {
			token.Claims[k] = v
		}
	}

	// Generate encoded token
	return token.SignedString([]byte(key))
}
