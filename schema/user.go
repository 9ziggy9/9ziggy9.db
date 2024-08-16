package schema

import (
	"database/sql"
	"golang.org/x/crypto/bcrypt"
	cmn "github.com/9ziggy9/9ziggy9.db/common"
)

const SQL_USERS_BOOTSTRAP = `
	CREATE TABLE users (
			id SERIAL PRIMARY KEY,
			name VARCHAR(255) NOT NULL UNIQUE,
			pwd  VARCHAR(255) NOT NULL
	);
`;

type User struct {
	ID   uint64 `json:"id"`;
	Name string `json:"name"`;
	Pwd  []byte `json:"-"`;
};

func (u *User) Commit(db *sql.DB) cmn.Result[uint64] {
	var id uint64;
	err := db.QueryRow(
		"INSERT INTO users (name, pwd) VALUES ($1, $2) RETURNING id",
		u.Name, u.Pwd,
	).Scan(&id);
	if err != nil { return cmn.Err[uint64]("failed to commit user"); }
	return cmn.Ok[uint64](id);
}

func (u *User) PasswordCompare(pwd string) bool {
	err := bcrypt.CompareHashAndPassword(u.Pwd, []byte(pwd));
	if err != nil { return false; }
	return true;
}

func CreateUser(name string, unsafe_pwd string) cmn.Result[User] {
	pwd, err := bcrypt.GenerateFromPassword(
		[]byte(unsafe_pwd),
		bcrypt.DefaultCost,
	);
	if err != nil { return cmn.Err[User]("failed to hash password"); }
	return cmn.Ok[User](User{ Name: name, Pwd: pwd });
}
