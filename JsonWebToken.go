package github.com/go-huhu/jwt

import (
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"time"
)

// todo:生成token
func SetToken(val []byte, timeout time.Duration, AppKey string) (string, error) {
	// 颁发一个有限期一小时的证书
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"val": val,
		"exp": time.Now().Add(timeout).Unix(),
		"iat": time.Now().Unix(),
	})
	tokenString, err := token.SignedString([]byte(AppKey))
	return tokenString, err
}

// todo:解析token
func AnalysisToken(tokenString, AppKey string) ([]byte, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		hmacSampleSecret := []byte(AppKey)
		return hmacSampleSecret, nil

	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		v, err := json.Marshal(claims)
		if err != nil {
			return nil, fmt.Errorf("json marshal error: %v", err)
		}
		return v, nil
	} else {
		return nil, fmt.Errorf("token Analysis error: %v", err)
	}

}
