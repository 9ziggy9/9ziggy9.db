package routes

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/9ziggy9/9ziggy9.db/schema"

	// srv "github.com/9ziggy9/9ziggy9.db/server"
	"github.com/dgrijalva/jwt-go"
)

// RANDOMIZE
var jwtKey = []byte("SUPER_SECRET");

type JwtClaims struct {
	Name string `json:"name"`;
	ID   uint64 `json:"id"`;
	jwt.StandardClaims;
}

type contextKey string
const (
	NameKey contextKey = "name"
	IdKey   contextKey = "name"
	RoleKey contextKey = "role"
)

func JwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// BEGIN: unprotected routes
		if r.URL.Path == "/login" {
			next.ServeHTTP(w, r)
			return;
		}
		// END: unprotected routes

		tkn_cookie, err := r.Cookie("token");
		if err != nil {
			http.Error(w, "missing token", http.StatusUnauthorized);
			return;
		}

		tkn_str  := tkn_cookie.Value;
		claims   := &JwtClaims{};
		tkn, err := jwt.ParseWithClaims(
			tkn_str, claims,
			func(tkn *jwt.Token) (interface{}, error) {
				return jwtKey, nil
			},
		);

		if err != nil || !tkn.Valid {
			http.Error(w, "invalid token", http.StatusUnauthorized);
			return;
		}

		ctx := context.WithValue(r.Context(), NameKey, claims.Name);
		ctx  = context.WithValue(ctx, IdKey, claims.ID);
		ctx  = context.WithValue(ctx, RoleKey, "standard");

		next.ServeHTTP(w, r.WithContext(ctx));
	});
}

func Login(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.FormValue("name");
		pwd  := r.FormValue("pwd");

		maybe_user := schema.GetUser(db, name);
		if maybe_user.Err != nil {
			http.Error(w, maybe_user.Err.Error(), http.StatusInternalServerError);
			return;
		}

		user := maybe_user.Data;
		if user.PwdOK(pwd) == true {
			tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, &JwtClaims{
				Name: user.Name,
				ID: user.ID,
				StandardClaims: jwt.StandardClaims{
					ExpiresAt: time.Now().Add(2 * time.Minute).Unix(),
				},
			});

			tkn_str, err := tkn.SignedString(jwtKey);
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError);
				return;
			}

			http.SetCookie(w, &http.Cookie{
				Name: "token",
				HttpOnly: true,
				Value: tkn_str,
				Path: "/",
				// Secure:   true, // Ensures the cookie is sent over HTTPS
				// SameSite: http.SameSiteStrictMode, // Prevents CSRF attacks
			})

			w.Header().Set("Content-Type", "application/json");
			if err := json.NewEncoder(w).Encode(user); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError);
				return;
			}
		} else {
			http.Error(w, "invalid password", http.StatusUnauthorized);
		}
	}
}
