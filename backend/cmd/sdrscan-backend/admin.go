package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/sdrscan/sdrscan/backend/internal/auth"
	"github.com/sdrscan/sdrscan/backend/internal/config"
	"github.com/sdrscan/sdrscan/backend/internal/db"
	"github.com/sdrscan/sdrscan/backend/internal/store"
)

func openStore(ctx context.Context, migrate bool) (*store.Store, func(), error) {
	cfg, err := config.FromEnv()
	if err != nil {
		return nil, nil, err
	}
	pool, err := db.Connect(ctx, cfg.DatabaseURL, true)
	if err != nil {
		return nil, nil, err
	}
	if migrate {
		if err := db.Migrate(ctx, pool); err != nil {
			pool.Close()
			return nil, nil, err
		}
	}
	return store.New(pool), pool.Close, nil
}

func cmdMigrate(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, closeFn, err := openStore(ctx, true)
	if err != nil {
		return err
	}
	closeFn()
	fmt.Println("migrations are up to date")
	return nil
}

func readPassword(fromStdin bool) (string, error) {
	if fromStdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", errors.New("no password on stdin")
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("stdin is not a terminal; use --password-stdin")
	}
	fmt.Fprint(os.Stderr, "Password: ")
	p1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "Repeat password: ")
	p2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(p1) != string(p2) {
		return "", errors.New("passwords do not match")
	}
	return string(p1), nil
}

func cmdUser(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: user create|list|reset-password|set-role|enable|disable [flags]")
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("user "+sub, flag.ContinueOnError)
	username := fs.String("username", "", "username")
	role := fs.String("role", "member", "admin or member")
	canDAST := fs.Bool("can-run-dast", false, "allow DAST (members)")
	pwStdin := fs.Bool("password-stdin", false, "read the password from stdin")
	mustChange := fs.Bool("must-change-password", true, "force a password change at first login")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	st, closeFn, err := openStore(ctx, true)
	if err != nil {
		return err
	}
	defer closeFn()
	h := auth.NewHasher()

	switch sub {
	case "list":
		us, _, err := st.ListUsers(ctx, store.Page{Page: 1, Size: 1000})
		if err != nil {
			return err
		}
		for _, u := range us {
			fmt.Printf("%d\t%s\t%s\tdast=%v\tactive=%v\n", u.ID, u.Username, u.Role, u.CanRunDAST, u.IsActive)
		}
		return nil
	case "create":
		if *username == "" {
			return errors.New("--username is required")
		}
		pw, err := readPassword(*pwStdin)
		if err != nil {
			return err
		}
		if err := auth.ValidatePassword(pw, *username, ""); err != nil {
			return err
		}
		hash, err := h.Hash(pw)
		if err != nil {
			return err
		}
		if *role != "admin" && *role != "member" {
			return errors.New("--role must be admin or member")
		}
		u, err := st.CreateUser(ctx, *username, hash, *role, *canDAST, *mustChange)
		if err != nil {
			return err
		}
		st.Audit(ctx, nil, nil, "cli", "user_created", u.Username+" ("+u.Role+")")
		fmt.Printf("created user %s (id %d, role %s)\n", u.Username, u.ID, u.Role)
		return nil
	}

	if *username == "" {
		return errors.New("--username is required")
	}
	u, err := st.GetUserByUsername(ctx, *username)
	if err != nil {
		return fmt.Errorf("user %q: %w", *username, err)
	}
	switch sub {
	case "reset-password":
		pw, err := readPassword(*pwStdin)
		if err != nil {
			return err
		}
		if err := auth.ValidatePassword(pw, u.Username, ""); err != nil {
			return err
		}
		hash, err := h.Hash(pw)
		if err != nil {
			return err
		}
		if err := st.SetPassword(ctx, u.ID, hash, true, ""); err != nil {
			return err
		}
		st.Audit(ctx, nil, nil, "cli", "password_reset", u.Username)
		fmt.Println("password reset; the user must change it at next login")
	case "set-role":
		_, changes, err := st.UpdateUser(ctx, u.ID, store.UserPatch{Role: role})
		if err != nil {
			return err
		}
		for _, c := range changes {
			st.Audit(ctx, nil, nil, "cli", c.Action, c.Target)
		}
		fmt.Println("role updated")
	case "enable", "disable":
		active := sub == "enable"
		_, changes, err := st.UpdateUser(ctx, u.ID, store.UserPatch{IsActive: &active})
		if err != nil {
			return err
		}
		for _, c := range changes {
			st.Audit(ctx, nil, nil, "cli", c.Action, c.Target)
		}
		fmt.Println("user " + sub + "d")
	default:
		return fmt.Errorf("unknown user command %q", sub)
	}
	return nil
}

func cmdToken(args []string) error {
	if len(args) == 0 || args[0] != "create" {
		return errors.New("usage: token create --name <label> [--project-id <id>]")
	}
	fs := flag.NewFlagSet("token create", flag.ContinueOnError)
	name := fs.String("name", "", "token label")
	projectID := fs.Int64("project-id", 0, "restrict the token to one project")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if strings.TrimSpace(*name) == "" {
		return errors.New("--name is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, closeFn, err := openStore(ctx, true)
	if err != nil {
		return err
	}
	defer closeFn()
	var pid *int64
	if *projectID > 0 {
		pid = projectID
	}
	raw := "sdrscan_" + auth.NewToken(32)
	if _, err := st.CreateToken(ctx, strings.TrimSpace(*name), auth.HashToken(raw), raw[8:16], pid, nil); err != nil {
		return err
	}
	st.Audit(ctx, nil, nil, "cli", "token_created", *name)
	fmt.Println(raw)
	fmt.Fprintln(os.Stderr, "Store this token now; it is not shown again.")
	return nil
}

func cmdMaintenance(args []string) error {
	if len(args) == 0 || args[0] != "rebuild-state" {
		return errors.New("usage: maintenance rebuild-state [--codebase-id <id>]")
	}
	fs := flag.NewFlagSet("rebuild-state", flag.ContinueOnError)
	cb := fs.Int64("codebase-id", 0, "only this codebase")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	st, closeFn, err := openStore(ctx, true)
	if err != nil {
		return err
	}
	defer closeFn()
	n, err := st.RebuildState(ctx, *cb)
	if err != nil {
		return err
	}
	fmt.Printf("rebuilt the current state of %d codebase(s)\n", n)
	return nil
}
