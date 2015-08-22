package jwt

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/lunny/tango"
)

type JwtAction struct {
	Auther
}

func (j *JwtAction) Get() string {
	return "JwtAction"
}

type NoJwtAction struct {
}

func (n *NoJwtAction) Get() string {
	return "NoJwtAction"
}

func TestJwt(t *testing.T) {
	tg := tango.Classic()
	tg.Use(New(Options{
		KeyFunc: func(ctx *tango.Context) (string, error) {
			return "", nil
		},
	}))
	tg.Any("/jwt", new(JwtAction))
	tg.Any("/noJwt", new(NoJwtAction))


	recorder := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "http://localhost:8000/jwt", nil)
	if err != nil {
		t.Error(err)
	}

	tg.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusUnauthorized)
	expect(t, recorder.Body.String(), http.StatusText(http.StatusUnauthorized))


	recorder = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "http://localhost:8000/noJwt", nil)
	if err != nil {
		t.Error(err)
	}

	tg.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusOK)
	expect(t, recorder.Body.String(), "NoJwtAction")


	recorder = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "http://localhost:8000/jwt", nil)
	if err != nil {
		t.Error(err)
	}

	token, err := NewToken("JWT")
	if err != nil {
		t.Error(err)
	}
	req.Header.Add("Authorization", "Bearer "+token)

	tg.ServeHTTP(recorder, req)
	expect(t, recorder.Code, http.StatusOK)
	expect(t, recorder.Body.String(), "JwtAction")
}

/* Test Helpers */
func expect(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		t.Errorf("Expected %v (type %v) - Got %v (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}

func refute(t *testing.T, a interface{}, b interface{}) {
	if a == b {
		t.Errorf("Did not expect %v (type %v) - Got %v (type %v)", b, reflect.TypeOf(b), a, reflect.TypeOf(a))
	}
}