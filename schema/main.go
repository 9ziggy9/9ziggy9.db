package schema

import (
	"database/sql"
	srv "github.com/9ziggy9/9ziggy9.db/server"
)

func TableExists(db *sql.DB, tableName string) (bool, error) {
	query := `
	SELECT EXISTS (
		SELECT 1 
		FROM information_schema.tables 
		WHERE table_schema = 'public' 
		AND table_name = $1
	);`
	var exists bool
	err := db.QueryRow(query, tableName).Scan(&exists)
	return exists, err
}

func BootstrapTable(db *sql.DB, sql_str string) {
	exists, err := TableExists(db, "users");
	if err != nil {
		srv.Log(srv.ERROR, "%s\n", err);
	} else if exists == false {
		_, err := db.Exec(sql_str);
		if err != nil { srv.Log(srv.ERROR, "%s\n", err); }
		srv.Log(srv.SUCCESS, "'users' table created");
	} else {
		srv.Log(srv.INFO, "'users' table already exists");
	}
}
