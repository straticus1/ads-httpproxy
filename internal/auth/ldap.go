package auth

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"ads-httpproxy/internal/config"
	"ads-httpproxy/pkg/logging"

	"github.com/go-ldap/ldap/v3"
	"go.uber.org/zap"
)

// LDAPAuthenticator implements LDAP/Active Directory authentication
type LDAPAuthenticator struct {
	cfg    *config.LDAPConfig
	logger *zap.Logger
}

func NewLDAPAuthenticator(cfg *config.LDAPConfig, logger *zap.Logger) (*LDAPAuthenticator, error) {
	if cfg == nil {
		return nil, errors.New("ldap config missing")
	}

	if cfg.URL == "" {
		return nil, errors.New("ldap url required")
	}

	if cfg.BindDN == "" || cfg.BindPassword == "" {
		return nil, errors.New("ldap bind credentials required")
	}

	return &LDAPAuthenticator{
		cfg:    cfg,
		logger: logger,
	}, nil
}

func (a *LDAPAuthenticator) Challenge(req *http.Request) (string, error) {
	realm := a.cfg.Realm
	if realm == "" {
		realm = "LDAP Authentication"
	}
	return fmt.Sprintf("Basic realm=\"%s\"", realm), nil
}

func (a *LDAPAuthenticator) Authenticate(req *http.Request) (bool, string, string, error) {
	// Get credentials from Proxy-Authorization or Authorization header
	username, password, ok := req.BasicAuth()
	if !ok {
		// Try Proxy-Authorization
		authHeader := req.Header.Get("Proxy-Authorization")
		if authHeader != "" && strings.HasPrefix(authHeader, "Basic ") {
			req.Header.Set("Authorization", authHeader)
			username, password, ok = req.BasicAuth()
		}
	}

	if !ok || username == "" || password == "" {
		return false, "", "", nil
	}

	// Connect to LDAP server
	conn, err := a.connect()
	if err != nil {
		a.logger.Error("Failed to connect to LDAP", zap.Error(err))
		return false, "", "", err
	}
	defer conn.Close()

	// Bind with service account
	err = conn.Bind(a.cfg.BindDN, a.cfg.BindPassword)
	if err != nil {
		a.logger.Error("Failed to bind to LDAP", zap.Error(err))
		return false, "", "", err
	}

	// Search for user
	userDN, userAttrs, err := a.searchUser(conn, username)
	if err != nil {
		a.logger.Debug("User not found in LDAP", zap.String("username", username), zap.Error(err))
		return false, "", "", nil
	}

	// Authenticate user by attempting to bind with their credentials
	err = conn.Bind(userDN, password)
	if err != nil {
		a.logger.Debug("LDAP authentication failed", zap.String("username", username), zap.Error(err))
		return false, "", "", nil
	}

	// Check group membership if required
	if len(a.cfg.RequireGroups) > 0 {
		isMember, err := a.checkGroupMembership(conn, userDN, a.cfg.RequireGroups)
		if err != nil {
			a.logger.Error("Failed to check group membership", zap.Error(err))
			return false, "", "", err
		}
		if !isMember {
			a.logger.Debug("User not in required groups", zap.String("username", username))
			return false, "", "", nil
		}
	}

	// Get user's full name/email for logging
	displayName := username
	if email, ok := userAttrs["mail"]; ok && len(email) > 0 {
		displayName = email[0]
	} else if cn, ok := userAttrs["cn"]; ok && len(cn) > 0 {
		displayName = cn[0]
	}

	a.logger.Info("LDAP authentication successful",
		zap.String("username", username),
		zap.String("display_name", displayName),
		zap.String("dn", userDN))

	return true, displayName, "", nil
}

// connect establishes connection to LDAP server
func (a *LDAPAuthenticator) connect() (*ldap.Conn, error) {
	// Parse LDAP URL
	if strings.HasPrefix(a.cfg.URL, "ldaps://") {
		// LDAPS (LDAP over TLS)
		host := strings.TrimPrefix(a.cfg.URL, "ldaps://")
		tlsConfig := &tls.Config{
			InsecureSkipVerify: a.cfg.InsecureSkipVerify,
			ServerName:         strings.Split(host, ":")[0],
		}
		conn, err := ldap.DialTLS("tcp", host, tlsConfig)
		if err != nil {
			return nil, err
		}
		return conn, nil
	}

	// LDAP (plain or with StartTLS)
	host := strings.TrimPrefix(a.cfg.URL, "ldap://")
	conn, err := ldap.Dial("tcp", host)
	if err != nil {
		return nil, err
	}

	// Use StartTLS if configured
	if a.cfg.StartTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: a.cfg.InsecureSkipVerify,
			ServerName:         strings.Split(host, ":")[0],
		}
		err = conn.StartTLS(tlsConfig)
		if err != nil {
			conn.Close()
			return nil, err
		}
	}

	// Set timeout
	if a.cfg.Timeout > 0 {
		conn.SetTimeout(time.Duration(a.cfg.Timeout) * time.Second)
	}

	return conn, nil
}

// searchUser finds the user's DN in LDAP
func (a *LDAPAuthenticator) searchUser(conn *ldap.Conn, username string) (string, map[string][]string, error) {
	// Build search filter
	filter := a.cfg.UserFilter
	if filter == "" {
		// Default filters
		if a.cfg.UserAttribute == "" {
			a.cfg.UserAttribute = "uid" // LDAP default
		}
		filter = fmt.Sprintf("(%s=%s)", a.cfg.UserAttribute, ldap.EscapeFilter(username))
	} else {
		// Replace {username} placeholder
		filter = strings.ReplaceAll(filter, "{username}", ldap.EscapeFilter(username))
	}

	// Attributes to retrieve
	attrs := []string{"dn", "cn", "mail", "memberOf", "sAMAccountName", "userPrincipalName"}
	if a.cfg.UserAttribute != "" {
		attrs = append(attrs, a.cfg.UserAttribute)
	}

	// Search
	searchRequest := ldap.NewSearchRequest(
		a.cfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, // No size limit
		0, // No time limit
		false,
		filter,
		attrs,
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return "", nil, err
	}

	if len(sr.Entries) == 0 {
		return "", nil, fmt.Errorf("user not found")
	}

	if len(sr.Entries) > 1 {
		logging.Logger.Warn("Multiple LDAP entries found for user", zap.String("username", username))
	}

	entry := sr.Entries[0]
	attrs_map := make(map[string][]string)
	for _, attr := range entry.Attributes {
		attrs_map[attr.Name] = attr.Values
	}

	return entry.DN, attrs_map, nil
}

// checkGroupMembership verifies user is in required groups
func (a *LDAPAuthenticator) checkGroupMembership(conn *ldap.Conn, userDN string, requiredGroups []string) (bool, error) {
	// Get user's groups
	searchRequest := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"memberOf"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return false, err
	}

	if len(sr.Entries) == 0 {
		return false, fmt.Errorf("user DN not found")
	}

	// Get user's groups
	userGroups := sr.Entries[0].GetAttributeValues("memberOf")

	// Check if user is in any of the required groups
	for _, reqGroup := range requiredGroups {
		for _, userGroup := range userGroups {
			// Match by CN or full DN
			if strings.Contains(strings.ToLower(userGroup), strings.ToLower(reqGroup)) {
				return true, nil
			}
		}
	}

	return false, nil
}

// GetUserGroups returns all groups a user belongs to
func (a *LDAPAuthenticator) GetUserGroups(username string) ([]string, error) {
	conn, err := a.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	err = conn.Bind(a.cfg.BindDN, a.cfg.BindPassword)
	if err != nil {
		return nil, err
	}

	userDN, _, err := a.searchUser(conn, username)
	if err != nil {
		return nil, err
	}

	searchRequest := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"memberOf"},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	if len(sr.Entries) == 0 {
		return []string{}, nil
	}

	return sr.Entries[0].GetAttributeValues("memberOf"), nil
}

// ActiveDirectoryAuthenticator is an alias for LDAPAuthenticator with AD-specific defaults
type ActiveDirectoryAuthenticator struct {
	*LDAPAuthenticator
}

func NewActiveDirectoryAuthenticator(cfg *config.LDAPConfig, logger *zap.Logger) (*ActiveDirectoryAuthenticator, error) {
	// Set AD-specific defaults if not configured
	if cfg.UserAttribute == "" {
		cfg.UserAttribute = "sAMAccountName" // AD uses sAMAccountName instead of uid
	}
	if cfg.UserFilter == "" {
		cfg.UserFilter = "(&(objectClass=user)(objectCategory=person)(sAMAccountName={username}))"
	}

	ldapAuth, err := NewLDAPAuthenticator(cfg, logger)
	if err != nil {
		return nil, err
	}

	return &ActiveDirectoryAuthenticator{
		LDAPAuthenticator: ldapAuth,
	}, nil
}
