package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
	"database/sql"
	"net"
	"net/http"
	_ "github.com/lib/pq"

	srv "github.com/9ziggy9/9ziggy9.db/server"
			"github.com/9ziggy9/9ziggy9.db/schema"
			"github.com/9ziggy9/9ziggy9.db/routes"
)

func LoadEnv(filename string) error {
	srv.Log(srv.INFO, "loading environment variables from %s ...", filename);
	defer srv.Log(srv.SUCCESS, "environmental variables loaded");

	file, err := os.Open(filename); if err != nil { return err; }
	defer file.Close();

	scanner := bufio.NewScanner(file);

	for scanner.Scan() {
		line := scanner.Text();
		if len(line) == 0 || strings.HasPrefix(line, "#") { continue; } // comments

		kvp := strings.SplitN(line, "=", 2);
		if len(kvp) != 2 { continue; }

		k := strings.TrimSpace(kvp[0]);
		v := strings.TrimSpace(kvp[1]);
		os.Setenv(k, v);
	}
	return scanner.Err();
}

const ENV_FILE string = "./.env";

func routesMain(db *sql.DB) *http.ServeMux {
	mux := http.NewServeMux();
	mux.HandleFunc("GET /users",  routes.GetUsers(db));
	mux.HandleFunc("POST /users", routes.CreateUser(db));
	mux.HandleFunc("POST /login", routes.Login(db));
	mux.HandleFunc("GET /logout", routes.Logout());
	return mux;
}

func tcpConnect() net.Listener {
	defer srv.Log(srv.SUCCESS, "successfully opened TCP connection");
	tcp_in, err := net.Listen("tcp", ":"+os.Getenv("PORT"));
	if err != nil {
		srv.Log(srv.ERROR, "failed to open TCP connection\n  -> %v", err);
	}
	return tcp_in;
}

func init() {
	if err := LoadEnv(ENV_FILE); err != nil {
		srv.Log(srv.ERROR, "failed to load environment variables:\n%v", err);
	}
}

func main() {
	db_conn_str := fmt.Sprintf("user=%s dbname=%s sslmode=disable",
		os.Getenv("DB_USER"), os.Getenv("DB"));

	db, err := sql.Open("postgres", db_conn_str);
	if err != nil { srv.Log(srv.ERROR, "%s\n", err); }
	defer db.Close();

	if err = db.Ping(); err != nil { srv.Log(srv.ERROR, "%s\n", err); }

	srv.Log(srv.SUCCESS, "connected to database");

	if exists, _ := schema.TableExists(db, "users"); exists == false {
		schema.BootstrapTable(db, schema.SQL_USERS_BOOTSTRAP);
	}

	tcp_in := tcpConnect();

	server := &http.Server{
		Handler: routes.JwtMiddleware(
			routesMain(db),
			[]string{"/login", "/logout"},
		),
		ReadTimeout:  time.Second * 10,
		WriteTimeout: time.Second * 10,
	}

	err_ch := make(chan error, 1);

	go func() { err_ch <- server.Serve(tcp_in); }();

	select {
	case err := <- err_ch: srv.Log(srv.ERROR, "%v\n", err);
	}
}
