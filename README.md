# jwt middleware for [tango](http://github.com/lunny/tango)

**Development**

Use example:

```Go
import (
    "net/http"

    "github.com/lunny/tango"
    "github.com/tango-contrib/jwt"
)

var (
    key = "mykey"
)

type JwtAction struct {
    jwt.Auther
}

func (j *JwtAction) Get() string {
    return j.GetClaim("username")
}

func main() {
    tg := tango.Classic()
    tg.Use(jwt.New(jwt.Options{
        KeyFunc: func(ctx *tango.Context) (string, error) {
            return key, nil
        },
    }))
    tg.Any("/jwt", new(JwtAction))

    go tg.Run()

    token, err := jwt.NewToken(key, map[string]interface{}{
            "username": name,
        })

    req, err := http.NewRequst("GET","http://localhost:8000/jwt", nil)
    req.Header.Add("Authorization", "Bearer "+token)

    http.Do(req)
}
```
```
