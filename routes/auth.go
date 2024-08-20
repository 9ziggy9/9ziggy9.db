package routes

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/9ziggy9/9ziggy9.db/schema"
	srv "github.com/9ziggy9/9ziggy9.db/server"
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

func CorsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "http://localhost:9002" || origin == "http://127.0.0.1:9002" {
			w.Header().Set("Access-Control-Allow-Origin", origin);
			w.Header().Set(
				"Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS",
			);
			w.Header().Set(
				"Access-Control-Allow-Headers", "Content-Type, Authorization",
			);
			w.Header().Set("Access-Control-Allow-Credentials", "true");
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return
			}
		} else {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func JwtMiddleware(next http.Handler, unprotected []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, path := range unprotected {
			if r.URL.Path == path {
				next.ServeHTTP(w, r)
				return;
			}
		}

		tkn_cookie, err := r.Cookie("token");
		if err != nil {
			srv.Log(srv.ERROR, "missing jwt in request");
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
			srv.Log(srv.ERROR, "invalid jwt in request");
			http.Error(w, "invalid token", http.StatusUnauthorized);
			return;
		}

		ctx := context.WithValue(r.Context(), NameKey, claims.Name);
		ctx  = context.WithValue(ctx, IdKey, claims.ID);
		ctx  = context.WithValue(ctx, RoleKey, "standard");

		next.ServeHTTP(w, r.WithContext(ctx));
	});
}

func Status(w http.ResponseWriter, r *http.Request) {
    tkn_cookie, err := r.Cookie("token");
    if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized);
			srv.Log(srv.ERROR, "couldn't find tkn_cookie");
			return;
    }

    tkn_str := tkn_cookie.Value
    claims := &JwtClaims{}
    tkn, err := jwt.ParseWithClaims(
			tkn_str, claims,
			func(tkn *jwt.Token) (interface{}, error) { return jwtKey, nil },
    )

    if err != nil || !tkn.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized);
			srv.Log(srv.ERROR, "unauthorized access");
			return;
    }

    response := map[string]string{
			"status": "authenticated",
			"name":   claims.Name,
			"id":     fmt.Sprintf("%d", claims.ID),
    }
    w.Header().Set("Content-Type", "application/json");
    w.WriteHeader(http.StatusOK);
    json.NewEncoder(w).Encode(response);
}

func Login(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.FormValue("name");
		pwd  := r.FormValue("pwd");
		reg  := r.FormValue("reg");

		isRegistering := false;
		if reg != "" {
			var err error;
			isRegistering, err = strconv.ParseBool(reg)
			if err != nil {
				http.Error(w, "boolean value error", http.StatusInternalServerError);
				srv.Log(srv.ERROR, "invalid bool value: %v\n", err);
				return;
			}
			if isRegistering == true {
				maybe_already_user := schema.GetUser(db, name);
				if maybe_already_user.Err == nil {
					http.Error(w, "user already exists", http.StatusUnauthorized);
					srv.Log(srv.ERROR, "user already exists " + name);
					return;
				}
				maybe_user := schema.CreateUser(name, pwd);
				if maybe_user.Err != nil {
					http.Error(w, maybe_user.Err.Error(), http.StatusInternalServerError);
					srv.Log(srv.ERROR, "failed to create user " + name);
					return;
				}
				maybe_data := maybe_user.Data.Commit(db);
				if maybe_data.Err != nil {
					http.Error(w, maybe_user.Err.Error(), http.StatusInternalServerError);
					srv.Log(srv.ERROR, "failed to commit user " + name);
					return;
				}
				srv.Log(srv.SUCCESS, "successfully created user " + name);
			}
		}

		maybe_user := schema.GetUser(db, name);
		if maybe_user.Err != nil {
			http.Error(w, maybe_user.Err.Error(), http.StatusInternalServerError);
			srv.Log(srv.ERROR, "failed to find user " + name);
			return;
		}

		user := maybe_user.Data;
		if user.PwdOK(pwd) == true {
			tkn := jwt.NewWithClaims(jwt.SigningMethodHS256, &JwtClaims{
				Name: user.Name,
				ID: user.ID,
				StandardClaims: jwt.StandardClaims{
					ExpiresAt: time.Now().Add(30 * time.Minute).Unix(),
				},
			});

			tkn_str, err := tkn.SignedString(jwtKey);
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError);
				return;
			}

			http.SetCookie(w, &http.Cookie{
				Name		 : "token",
				HttpOnly : true,
				Value		 : tkn_str,
				Path		 : "/",
				SameSite : http.SameSiteLaxMode,
				// Secure:   true, // Ensures the cookie is sent over HTTPS
			})

			w.Header().Set("Content-Type", "application/json");
			if err := json.NewEncoder(w).Encode(user); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError);
				return;
			}
			srv.Log(srv.SUCCESS, "user " + user.Name + " logged in");
		} else {
			http.Error(w, "invalid password", http.StatusUnauthorized);
		}
	}
}

func Logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "token",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Expires:  time.Unix(0, 0), // set expiration date in the past
			MaxAge:   -1,              // forces the cookie to expire immediately
		})
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("logged out successfully"))
	}
}
