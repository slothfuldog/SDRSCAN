package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sdrscan/sdrscan/backend/internal/apierr"
)

// CreateUser inserts a user. A taken username yields apierr 409 username_taken.
func (s *Store) CreateUser(ctx context.Context, username, hash, role string, canDAST, mustChange bool) (User, error) {
	u, err := collectOne[User](s.Pool.Query(ctx, `INSERT INTO users (username, password_hash, role, can_run_dast, must_change_password)
		VALUES ($1, $2, $3, $4, $5) RETURNING `+userCols, username, hash, role, canDAST, mustChange))
	if IsUnique(err, "uq_users_username") {
		return User{}, apierr.Conflict("username_taken", "That username is already taken.").WithField("username")
	}
	return u, err
}

// GetUser loads a user by id.
func (s *Store) GetUser(ctx context.Context, id int64) (User, error) {
	return collectOne[User](s.Pool.Query(ctx, `SELECT `+userCols+` FROM users WHERE id = $1`, id))
}

// GetUserByUsername loads a user by case-insensitive username.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error) {
	return collectOne[User](s.Pool.Query(ctx, `SELECT `+userCols+` FROM users WHERE lower(username) = lower($1)`, username))
}

// CountUsers returns the number of users.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

// ListUsers returns a page of users ordered by id.
func (s *Store) ListUsers(ctx context.Context, p Page) ([]User, int, error) {
	var total int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&total); err != nil {
		return nil, 0, err
	}
	items, err := collectAll[User](s.Pool.Query(ctx, `SELECT `+userCols+` FROM users ORDER BY id LIMIT $1 OFFSET $2`, p.Size, p.Offset()))
	return items, total, err
}

// RecordLoginFailure increments the failure counter and locks the account for
// 15 minutes on the 5th consecutive failure. It returns locked_until (nil when
// not locked).
func (s *Store) RecordLoginFailure(ctx context.Context, id int64, maxFails int, lockFor time.Duration) (*time.Time, error) {
	var locked *time.Time
	err := s.Pool.QueryRow(ctx, `UPDATE users SET
			failed_attempts = CASE WHEN failed_attempts + 1 >= $2 THEN 0 ELSE failed_attempts + 1 END,
			locked_until = CASE WHEN failed_attempts + 1 >= $2 THEN now() + $3::interval ELSE locked_until END
		WHERE id = $1 RETURNING CASE WHEN failed_attempts = 0 THEN locked_until END`,
		id, maxFails, lockFor.String()).Scan(&locked)
	return locked, err
}

// RecordLoginSuccess resets the counters and stamps last_login_at.
func (s *Store) RecordLoginSuccess(ctx context.Context, id int64) error {
	_, err := s.Pool.Exec(ctx, `UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login_at = now() WHERE id = $1`, id)
	return err
}

// UpdateHash stores a re-computed password hash without touching other flags.
func (s *Store) UpdateHash(ctx context.Context, id int64, hash string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1`, id, hash)
	return err
}

// SetPassword changes the password. When keepSession is non-empty all other
// sessions of the user are revoked, otherwise all of them.
func (s *Store) SetPassword(ctx context.Context, id int64, hash string, mustChange bool, keepSession string) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE users SET password_hash = $2, must_change_password = $3,
		failed_attempts = 0, locked_until = NULL, updated_at = now() WHERE id = $1`, id, hash, mustChange); err != nil {
		return err
	}
	if keepSession == "" {
		_, err = tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, id)
	} else {
		_, err = tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1 AND id_hash <> $2`, id, keepSession)
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// UserPatch lists the fields an admin may change.
type UserPatch struct {
	Role       *string
	IsActive   *bool
	CanRunDAST *bool
}

// UserChange describes an applied change for the audit log.
type UserChange struct {
	Action string
	Target string
}

// UpdateUser applies a patch under the last-admin protection. Active admin rows
// are locked (ordered by id) so concurrent demotions serialise.
func (s *Store) UpdateUser(ctx context.Context, id int64, p UserPatch) (User, []UserChange, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return User{}, nil, err
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx, `SELECT id FROM users WHERE role = 'admin' AND is_active ORDER BY id FOR UPDATE`)
	if err != nil {
		return User{}, nil, err
	}
	activeAdmins, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return User{}, nil, err
	}
	cur, err := collectOne[User](tx.Query(ctx, `SELECT `+userCols+` FROM users WHERE id = $1 FOR UPDATE`, id))
	if err != nil {
		return User{}, nil, err
	}
	if p.Role != nil && *p.Role != "admin" && *p.Role != "member" {
		return User{}, nil, apierr.ValidationField("role", "role must be 'admin' or 'member'.")
	}
	newRole, newActive, newDAST := cur.Role, cur.IsActive, cur.CanRunDAST
	if p.Role != nil {
		newRole = *p.Role
	}
	if p.IsActive != nil {
		newActive = *p.IsActive
	}
	if p.CanRunDAST != nil {
		newDAST = *p.CanRunDAST
	}
	// Active admins after the change.
	remaining := 0
	for _, aid := range activeAdmins {
		if aid != cur.ID {
			remaining++
		}
	}
	if newRole == "admin" && newActive {
		remaining++
	}
	if remaining == 0 {
		return User{}, nil, apierr.Conflict("last_admin", "At least one active Admin must remain.")
	}
	var changes []UserChange
	if newRole != cur.Role {
		changes = append(changes, UserChange{"user_role_changed", cur.Username + " -> " + newRole})
	}
	if newActive != cur.IsActive {
		if newActive {
			changes = append(changes, UserChange{"user_enabled", cur.Username})
		} else {
			changes = append(changes, UserChange{"user_disabled", cur.Username})
		}
	}
	if newDAST != cur.CanRunDAST {
		v := "off"
		if newDAST {
			v = "on"
		}
		changes = append(changes, UserChange{"user_dast_access_changed", cur.Username + " -> " + v})
	}
	upd, err := collectOne[User](tx.Query(ctx, `UPDATE users SET role = $2, is_active = $3, can_run_dast = $4, updated_at = now()
		WHERE id = $1 RETURNING `+userCols, id, newRole, newActive, newDAST))
	if err != nil {
		return User{}, nil, err
	}
	if !newActive && cur.IsActive {
		if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, id); err != nil {
			return User{}, nil, err
		}
	}
	// Schedules owned by this user are suspended in the same transaction.
	susp, err := suspendOwnedSchedules(ctx, tx, id, !newActive, newRole == "admin" || newDAST)
	if err != nil {
		return User{}, nil, err
	}
	for _, s := range susp {
		changes = append(changes, UserChange{"schedule_suspended", s})
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, nil, err
	}
	return upd, changes, nil
}

// ----- sessions -----

// SessionInfo is a valid session joined with its (active) user.
type SessionInfo struct {
	IDHash string
	CSRF   string
	User   User
}

// CreateSession stores a session.
func (s *Store) CreateSession(ctx context.Context, userID int64, idHash, csrf string, absolute time.Duration) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO sessions (id_hash, user_id, csrf_token, expires_at)
		VALUES ($1, $2, $3, now() + $4::interval)`, idHash, userID, csrf, absolute.String())
	return err
}

// GetSession returns the session when it is neither idle nor absolutely
// expired and its user is active; the user row is read fresh so role and DAST
// permission changes apply to the very next request.
func (s *Store) GetSession(ctx context.Context, idHash string, idle time.Duration) (SessionInfo, error) {
	var si SessionInfo
	si.IDHash = idHash
	err := s.Pool.QueryRow(ctx, `SELECT s.csrf_token, u.id, u.username, u.password_hash, u.role, u.can_run_dast, u.is_active,
			u.must_change_password, u.failed_attempts, u.locked_until, u.last_login_at, u.created_at, u.updated_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.id_hash = $1 AND s.expires_at > now() AND s.last_seen_at > now() - $2::interval AND u.is_active`,
		idHash, idle.String()).Scan(&si.CSRF, &si.User.ID, &si.User.Username, &si.User.PasswordHash, &si.User.Role,
		&si.User.CanRunDAST, &si.User.IsActive, &si.User.MustChangePassword, &si.User.FailedAttempts,
		&si.User.LockedUntil, &si.User.LastLoginAt, &si.User.CreatedAt, &si.User.UpdatedAt)
	if err != nil {
		return si, notFound(err)
	}
	// Refresh last_seen_at at most once a minute.
	_, _ = s.Pool.Exec(ctx, `UPDATE sessions SET last_seen_at = now() WHERE id_hash = $1 AND last_seen_at < now() - interval '1 minute'`, idHash)
	return si, nil
}

// DeleteSession removes one session.
func (s *Store) DeleteSession(ctx context.Context, idHash string) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM sessions WHERE id_hash = $1`, idHash)
	return err
}

// PurgeSessions removes expired sessions.
func (s *Store) PurgeSessions(ctx context.Context, idle time.Duration) (int64, error) {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= now() OR last_seen_at <= now() - $1::interval`, idle.String())
	return tag.RowsAffected(), err
}

// ----- audit -----

// AuditEntry is a row of audit_log.
type AuditEntry struct {
	ID          int64     `db:"id"`
	At          time.Time `db:"at"`
	ActorUserID *int64    `db:"actor_user_id"`
	ActorName   string    `db:"actor_name"`
	Action      string    `db:"action"`
	Target      string    `db:"target"`
}

// Audit appends an audit row. It never fails the caller.
func (s *Store) Audit(ctx context.Context, q DBTX, actorID *int64, actorName, action, target string) {
	if q == nil {
		q = s.Pool
	}
	_, _ = q.Exec(context.WithoutCancel(ctx), `INSERT INTO audit_log (actor_user_id, actor_name, action, target) VALUES ($1, $2, $3, $4)`,
		actorID, actorName, action, target)
}

// ListAudit returns a page of audit rows, newest first.
func (s *Store) ListAudit(ctx context.Context, p Page) ([]AuditEntry, int, error) {
	var total int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_log`).Scan(&total); err != nil {
		return nil, 0, err
	}
	items, err := collectAll[AuditEntry](s.Pool.Query(ctx, `SELECT id, at, actor_user_id, actor_name, action, target
		FROM audit_log ORDER BY at DESC, id DESC LIMIT $1 OFFSET $2`, p.Size, p.Offset()))
	return items, total, err
}

// ----- ingest tokens -----

// Token is a row of ingest_tokens.
type Token struct {
	ID          int64      `db:"id"`
	Name        string     `db:"name"`
	TokenHash   string     `db:"token_hash"`
	TokenPrefix string     `db:"token_prefix"`
	ProjectID   *int64     `db:"project_id"`
	CreatedBy   *int64     `db:"created_by"`
	CreatedAt   time.Time  `db:"created_at"`
	LastUsedAt  *time.Time `db:"last_used_at"`
	RevokedAt   *time.Time `db:"revoked_at"`
}

const tokenCols = `id, name, token_hash, token_prefix, project_id, created_by, created_at, last_used_at, revoked_at`

// CreateToken stores a token hash.
func (s *Store) CreateToken(ctx context.Context, name, hash, prefix string, projectID, createdBy *int64) (Token, error) {
	t, err := collectOne[Token](s.Pool.Query(ctx, `INSERT INTO ingest_tokens (name, token_hash, token_prefix, project_id, created_by)
		VALUES ($1, $2, $3, $4, $5) RETURNING `+tokenCols, name, hash, prefix, projectID, createdBy))
	if IsFKViolation(err) {
		return Token{}, apierr.ValidationField("project_id", "project_id does not exist.")
	}
	return t, err
}

// TokenRow is a token with the names shown in the list.
type TokenRow struct {
	Token
	ProjectName   *string `db:"project_name"`
	CreatedByName *string `db:"created_by_name"`
}

// ListTokens returns a page of tokens, newest first.
func (s *Store) ListTokens(ctx context.Context, p Page) ([]TokenRow, int, error) {
	var total int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM ingest_tokens`).Scan(&total); err != nil {
		return nil, 0, err
	}
	items, err := collectAll[TokenRow](s.Pool.Query(ctx, `SELECT t.id, t.name, t.token_hash, t.token_prefix, t.project_id, t.created_by, t.created_at,
			t.last_used_at, t.revoked_at, p.name AS project_name, u.username AS created_by_name
		FROM ingest_tokens t LEFT JOIN projects p ON p.id = t.project_id LEFT JOIN users u ON u.id = t.created_by
		ORDER BY t.id DESC LIMIT $1 OFFSET $2`, p.Size, p.Offset()))
	return items, total, err
}

// GetTokenRow loads one token with names.
func (s *Store) GetTokenRow(ctx context.Context, id int64) (TokenRow, error) {
	return collectOne[TokenRow](s.Pool.Query(ctx, `SELECT t.id, t.name, t.token_hash, t.token_prefix, t.project_id, t.created_by, t.created_at,
			t.last_used_at, t.revoked_at, p.name AS project_name, u.username AS created_by_name
		FROM ingest_tokens t LEFT JOIN projects p ON p.id = t.project_id LEFT JOIN users u ON u.id = t.created_by WHERE t.id = $1`, id))
}

// RevokeToken sets revoked_at; false when it did not exist.
func (s *Store) RevokeToken(ctx context.Context, id int64) (Token, error) {
	return collectOne[Token](s.Pool.Query(ctx, `UPDATE ingest_tokens SET revoked_at = COALESCE(revoked_at, now()) WHERE id = $1 RETURNING `+tokenCols, id))
}

// LookupToken finds an active token by hash and stamps last_used_at.
func (s *Store) LookupToken(ctx context.Context, hash string) (Token, error) {
	return collectOne[Token](s.Pool.Query(ctx, `UPDATE ingest_tokens SET last_used_at = now()
		WHERE token_hash = $1 AND revoked_at IS NULL RETURNING `+tokenCols, hash))
}
