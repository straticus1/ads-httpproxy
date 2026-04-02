package browserid

import (
	"context"
	"net/http"
)

const CookieName = "__ads_bid"

type contextKey string

const IdentityContextKey contextKey = "browserid_identity"

// Middleware checks for a valid __ads_bid cookie. If present and valid, adds Identity to context.
// If absent or invalid, generates a new one, sets the cookie, and adds Identity to context.
func Middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var ident *Identity

		cookie, err := r.Cookie(CookieName)
		if err == nil && cookie.Value != "" {
			validIdent, err := Verify(cookie.Value)
			if err == nil {
				ident = validIdent
			}
		}

		if ident == nil {
			tokenStr, newIdent := Generate(r)
			ident = newIdent
			
			// Set the cookie
			http.SetCookie(w, &http.Cookie{
				Name:     CookieName,
				Value:    tokenStr,
				Path:     "/",
				MaxAge:   86400 * 365, // 1 year
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteNoneMode,
			})
		}

		ctx := context.WithValue(r.Context(), IdentityContextKey, ident)
		r = r.WithContext(ctx)

		next(w, r)
	}
}
