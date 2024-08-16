package main

import (
	"fmt"
	"bufio"
	"os"
	"strings"
	"database/sql"
	_ "github.com/lib/pq"
)

func LoadEnv(filename string) error {
	ServerLog(INFO, "loading environment variables from %s ...", filename)
	defer ServerLog(SUCCESS, "environmental variables loaded")

	file, err := os.Open(filename); if err != nil { return err }
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 || strings.HasPrefix(line, "#") { continue } // comments

		kvp := strings.SplitN(line, "=", 2)
		if len(kvp) != 2 { continue }

		k := strings.TrimSpace(kvp[0])
		v := strings.TrimSpace(kvp[1])
		os.Setenv(k, v)
	}
	return scanner.Err()
}

const ENV_FILE string = "./.env";

func init() {
	if err := LoadEnv(ENV_FILE); err != nil {
		ServerLog(ERROR, "failed to load environment variables:\n%v", err)
	}
}

func main() {
	fmt.Printf("PORT NUMBER: %s\n", os.Getenv("PORT"));
}
