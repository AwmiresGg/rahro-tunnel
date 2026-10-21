package auth

import "testing"

func TestPasswordHashVerify(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("correct horse battery staple", h) {
		t.Fatal("correct password should verify")
	}
	if VerifyPassword("wrong", h) {
		t.Fatal("wrong password must not verify")
	}
	if VerifyPassword("x", "not-a-valid-hash") {
		t.Fatal("malformed hash must not verify")
	}
}

func TestTokens(t *testing.T) {
	if NewToken(16) == NewToken(16) {
		t.Fatal("tokens should be unique")
	}
	if len(NewUUIDHex()) != 32 {
		t.Fatal("uuid hex must be 32 chars")
	}
	tok := NewAPIToken()
	if HashToken(tok) == tok {
		t.Fatal("hash must differ from token")
	}
	if HashToken(tok) != HashToken(tok) {
		t.Fatal("hash must be deterministic")
	}
}
