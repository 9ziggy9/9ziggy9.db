package routes

import (
	"net/http"
	"encoding/json"
	"github.com/9ziggy9/9ziggy9.db/schema"
	srv "github.com/9ziggy9/9ziggy9.db/server"
	"database/sql"
)

func GetUsers(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.Query("SELECT id, name, pwd FROM users");
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError);
			return;
		}
		defer rows.Close();

		var users []schema.User
		for rows.Next() {
			var user schema.User
			if err := rows.Scan(&user.ID, &user.Name, &user.Pwd); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError);
				return;
			}
			users = append(users, user);
		}

		if err := rows.Err(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json");
		if err := json.NewEncoder(w).Encode(users); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError);
		}
	}
};

func CreateUser(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user_from schema.User;
		if err := json.NewDecoder(r.Body).Decode(&user_from); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError);
			return;
		}

		new_user := schema.CreateUser(user_from.Name, string(user_from.Pwd));
		if new_user.Err != nil { srv.Log(srv.ERROR, "%s\n", new_user.Err); }

		commit_res := new_user.Data.Commit(db);
		if commit_res.Err != nil { srv.Log(srv.ERROR, "%s\n", commit_res.Err); }

		w.Header().Set("Content-Type", "application/json");
		w.WriteHeader(http.StatusCreated);
		if err := json.NewEncoder(w).Encode(commit_res.Data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError);
		}
	}
};
