package apierr

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestValidationFieldShape(t *testing.T) {
	e := ValidationField("login.password", "login.password is required.")
	if e.Status != http.StatusUnprocessableEntity || e.Code != "validation_failed" || FieldOf(e) != "login.password" {
		t.Fatalf("%+v", e)
	}
	b, _ := json.Marshal(e.Details)
	if string(b) != `{"field":"login.password"}` {
		t.Fatalf("details %s", b)
	}
}

func TestFieldErrorsCollector(t *testing.T) {
	var fe FieldErrors
	if fe.Err() != nil || fe.Len() != 0 {
		t.Fatal("empty collector must have no error")
	}
	fe.Add("name", "name is required.")
	one, _ := As(fe.Err())
	if one == nil || FieldOf(one) != "name" || FieldsOf(one)[0].Message != "name is required." {
		t.Fatalf("single: %+v", one)
	}
	if m, _ := one.Details.(map[string]any); m["fields"] != nil {
		t.Fatalf("a single failure carries no fields list: %v", m)
	}
	fe.Add("repo_url", "repo_url is required.")
	many, _ := As(fe.Err())
	if many.Message != "name is required." || FieldOf(many) != "name" || len(FieldsOf(many)) != 2 {
		t.Fatalf("multi: %+v", many)
	}
	b, _ := json.Marshal(many.Details)
	want := `{"field":"name","fields":[{"field":"name","message":"name is required."},{"field":"repo_url","message":"repo_url is required."}]}`
	if string(b) != want {
		t.Fatalf("details %s\nwant %s", b, want)
	}
}

func TestFieldErrorsKeepSpecificCode(t *testing.T) {
	var fe FieldErrors
	src := New(http.StatusUnprocessableEntity, "invalid_cron", "bad cron").WithField("cron")
	if !fe.AddError(src) {
		t.Fatal("422 errors are collected")
	}
	if got, _ := As(fe.Err()); got.Code != "invalid_cron" {
		t.Fatalf("single error keeps its code: %+v", got)
	}
	fe.Add("name", "name is required.")
	got, _ := As(fe.Err())
	if got.Code != "validation_failed" || FieldsOf(got)[0].Code != "invalid_cron" {
		t.Fatalf("multi: code %s, first %+v", got.Code, FieldsOf(got)[0])
	}
	if fe.AddError(Internal()) {
		t.Fatal("a non-validation error must not be collected")
	}
}
