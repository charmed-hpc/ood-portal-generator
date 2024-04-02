// Copyright 2024 Canonical Ltd.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package config

import (
	"bytes"
	"crypto/sha1"
	_ "embed"
	"fmt"
	"net"
	"os/exec"
	"reflect"
	"strings"
	"text/template"

	"github.com/mitchellh/mapstructure"
)

//go:embed templates/need-auth.conf.tmpl
var needAuthTmpl string

//go:embed templates/ood-portal.conf.tmpl
var oodPortalTmpl string

// Dex configuration for Open OnDemand.
type dex struct {
	Uri      string `mapstructure:"uri"`
	HttpPort int    `mapstructure:"http_port"`
}

// Google Analytics configuration for Open OnDemand.
type analytics struct {
	Url string `mapstructure:"url"`
	Id  string `mapstructure:"id"`
}

// Open OnDemand portal configuration options.
type portalConfig struct {
	// General options
	ListenAddrPort            []string  `mapstructure:"listen_addr_port"`
	ServerName                string    `mapstructure:"servername"`
	ServerAliases             []string  `mapstructure:"server_aliases"`
	ProxyServer               string    `mapstructure:"proxy_server"`
	AllowedHosts              []string  `mapstructure:"allowed_hosts"`
	Port                      int       `mapstructure:"port"`
	Ssl                       []string  `mapstructure:"ssl"`
	Protocol                  string    `mapstructure:"protocol"`
	DisableLogs               bool      `mapstructure:"disable_logs"`
	LogRoot                   string    `mapstructure:"logroot"`
	ErrorLog                  string    `mapstructure:"errorlog"`
	AccessLog                 string    `mapstructure:"accesslog"`
	LogFormat                 string    `mapstructure:"logformat"`
	UseRewrites               bool      `mapstructure:"use_rewrites"`
	UseMaintenance            bool      `mapstructure:"use_maintenance"`
	MaintenanceIPAllowlist    []string  `mapstructure:"maintenance_ip_allowlist"`
	SecurityCspFrameAncestors string    `mapstructure:"security_csp_frame_ancestors"`
	SecurityStrictTransport   bool      `mapstructure:"security_strict_transport"`
	LuaRoot                   string    `mapstructure:"lua_root"`
	LuaLogLevel               string    `mapstructure:"lua_log_level"`
	UserMapCmd                string    `mapstructure:"user_map_cmd"`
	UserMapMatch              string    `mapstructure:"user_map_match"`
	UserEnv                   string    `mapstructure:"user_env"`
	MapFailUri                string    `mapstructure:"map_fail_uri"`
	PunStageCmd               string    `mapstructure:"pun_stage_cmd"`
	Auth                      []string  `mapstructure:"auth"`
	CustomVhostDirectives     []string  `mapstructure:"custom_vhost_directives"`
	CustomLocationDirectives  []string  `mapstructure:"custom_location_directives"`
	RootUri                   string    `mapstructure:"root_uri"`
	Analytics                 analytics `mapstructure:"analytics"`

	// Public assets
	PublicUri  string `mapstructure:"public_uri"`
	PublicRoot string `mapstructure:"public_root"`

	// Logout redirect
	LogoutUri      string `mapstructure:"logout_uri"`
	LogoutRedirect string `mapstructure:"logout_redirect"`

	// Reverse proxy
	HostRegex string `mapstructure:"host_regex"`
	NodeUri   string `mapstructure:"node_uri"`
	RnodeUri  string `mapstructure:"rnode_uri"`

	// Per-user NGINX
	NginxUri          string `mapstructure:"nginx_uri"`
	PunUri            string `mapstructure:"pun_uri"`
	PunSocketRoot     string `mapstructure:"pun_socket_root"`
	PunMaxRetries     int    `mapstructure:"pun_max_retries"`
	PunPreHookRootCmd string `mapstructure:"pun_pre_hook_root_cmd"`
	PunPreHookExports string `mapstructure:"pun_pre_hook_exports"`

	// User registration
	RegisterUri  string `mapstructure:"register_uri"`
	RegisterRoot string `mapstructure:"register_root"`

	// OpenID Connect
	OidcUri                      string      `mapstructure:"oidc_uri"`
	OidcDiscoverUri              string      `mapstructure:"oidc_discover_uri"`
	OidcDiscoverRoot             string      `mapstructure:"oidc_discover_root"`
	OidcRedirectUri              string      `mapstructure:"oidc_redirect_uri"`
	OidcProviderMetadataUrl      string      `mapstructure:"oidc_provider_metadata_url"`
	OidcClientId                 string      `mapstructure:"oidc_client_id"`
	OidcClientSecret             string      `mapstructure:"oidc_client_secret"`
	OidcRemoteUserClaim          string      `mapstructure:"oidc_remote_user_claim"`
	OidcScope                    string      `mapstructure:"oidc_scope"`
	OidcCryptoPassphrase         string      `mapstructure:"oidc_crypto_passphrase"`
	OidcSessionInactivityTimeout int         `mapstructure:"oidc_session_inactivity_timeout"`
	OidcSessionMaxDuration       int         `mapstructure:"oidc_session_max_duration"`
	OidcStateMaxNumberOfCookies  string      `mapstructure:"oidc_state_max_number_of_cookies"`
	OidcCookieSameSite           string      `mapstructure:"oidc_cookie_same_site"`
	OidcSettings                 map[any]any `mapstructure:"oidc_settings"`

	// Dex OpenID Connect provider
	Dex dex `mapstructure:"dex"`
}

// Render the Open OnDemand portal configuration file from a template.
func (p portalConfig) Render() (out string, err error) {
	if p.IsAuthEnabled() {
		out, err = renderPortal(p)
	} else {
		out, err = renderNeedAuth(p)
	}

	return
}

// Determine if authentication is enabled for Open OnDemand.
//
// For authentication to be enabled, either Dex needs to be configured
// or the `auth` option is present in `ood_portal.yml`.
//
// Open OnDemand does not support running in unauthenticated mode;
// authentication must be enabled to access the portal.
func (p *portalConfig) IsAuthEnabled() bool {
	return len(p.Auth) == 0
}

// Create new Open OnDemand portal configuration from `ood_portal.yml`.
//
// This function will initialize certain defaults in the `portalConfig` struct
// if the mapped configuration option is omitted from `ood_portal.yml`. See
// the `ood_portal.yml` configuration file for the recommended defaults:
// https://osc.github.io/ood-documentation/latest/reference/files/ood-portal-yml.html
func NewPortalConfig(m map[string]any) (p portalConfig, err error) {
	// The proxy server's value, if omitted, is either the given
	// servername or the FQDN of the host.
	serverName, err := getServerName(m)
	if err != nil {
		return p, err
	}
	if _, ok := m["proxy_server"]; !ok {
		m["proxy_server"] = serverName
	}

	// Defaults determined by whether ssl is enabled or not.
	_, ssl_ok := m["ssl"]
	var port int
	var oidcCookieSameSite, logSuffix string
	if ssl_ok {
		m["protocol"] = "https://"
		port = 443
		oidcCookieSameSite = "Off"
		logSuffix = "_ssl.log"
	} else {
		m["protocol"] = "http://"
		port = 80
		oidcCookieSameSite = "On"
		logSuffix = ".log"
	}

	if _, ok := m["port"]; !ok {
		m["port"] = port
	}

	if _, ok := m["oidc_cookie_same_site"]; !ok {
		m["oidc_cookie_same_site"] = oidcCookieSameSite
	}

	// Set log configuration if it is omitted from `ood_portal.yaml`
	if _, ok := m["logroot"]; !ok {
		m["logroot"] = "logs"
	}

	if _, ok := m["accesslog"]; !ok {
		m["accesslog"] = fmt.Sprintf("%s/%s_access%s", m["logroot"], serverName, logSuffix)
	} else {
		m["accesslog"] = fmt.Sprintf("%s/%s", m["logroot"], m["accesslog"])
	}

	if _, ok := m["errorlog"]; !ok {
		m["errorlog"] = fmt.Sprintf("%s/%s_error%s", m["logroot"], serverName, logSuffix)
	} else {
		m["errorlog"] = fmt.Sprintf("%s/%s", m["logroot"], m["errorlog"])
	}

	// Set `user_map_match` if `user_map_cmd` is omitted and
	// `user_map_match` is also omitted from `ood_portal.yml`
	_, map_cmd_ok := m["user_map_cmd"]
	if _, ok := m["user_map_match"]; !ok && !map_cmd_ok {
		m["user_map_match"] = ".*"
	}

	// Set security configuration if it is omitted from `ood_portal.yml`
	if _, ok := m["security_csp_frame_ancestors"]; !ok {
		m["security_csp_frame_ancestors"] = fmt.Sprintf("%s%s", m["protocol"], m["proxy_server"])
	}

	if _, ok := m["security_strict_transport"]; !ok {
		m["security_strict_transport"] = ssl_ok
	}

	// Set OIDC redirect URI.
	if _, ok := m["oidc_uri"]; ok {
		m["oidc_redirect_uri"] = fmt.Sprintf("%s%s", m["protocol"], m["servername"])
	} else {
		m["oidc_redirect_uri"] = fmt.Sprintf("%s%s%s", m["protocol"], m["servername"], m["oidc_uri"])
	}

	// Set OIDC cypto passphrase if one has not been provided.
	if _, ok := m["oidc_crypto_passphrase"]; !ok {
		hex := sha1.New()
		m["oidc_crypto_passphrase"] = fmt.Sprintf("%x", hex.Sum([]byte(serverName)))
	}

	// Simply set recommended default if option is absent from `ood_portal.yml`
	if _, ok := m["disable_logs"]; !ok {
		m["disable_logs"] = false
	}

	if _, ok := m["use_rewrites"]; !ok {
		m["use_rewrites"] = true
	}

	if _, ok := m["lua_root"]; !ok {
		m["lua_root"] = "/opt/ood/mod_ood_proxy/lib"
	}

	if _, ok := m["lua_log_level"]; !ok {
		m["lua_log_level"] = "info"
	}

	if _, ok := m["pun_stage_cmd"]; !ok {
		m["pun_stage_cmd"] = "sudo /opt/ood/nginx_stage/sbin/nginx_stage"
	}

	if _, ok := m["use_maintenance"]; !ok {
		m["use_maintenance"] = true
	}

	if _, ok := m["root_uri"]; !ok {
		m["root_uri"] = "/pun/sys/dashboard"
	}

	if _, ok := m["public_uri"]; !ok {
		m["public_uri"] = "/public"
	}

	if _, ok := m["public_root"]; !ok {
		m["public_root"] = "/var/www/ood/public"
	}

	if _, ok := m["logout_uri"]; !ok {
		m["logout_uri"] = "/logout"
	}

	if _, ok := m["logout_redirect"]; !ok {
		m["logout_redirect"] = "/pun/sys/dashboard/logout"
	}

	if _, ok := m["host_regex"]; !ok {
		m["host_regex"] = "[^/]+"
	}

	if _, ok := m["nginx_uri"]; !ok {
		m["nginx_uri"] = "/nginx"
	}

	if _, ok := m["pun_uri"]; !ok {
		m["pun_uri"] = "/pun"
	}

	if _, ok := m["pun_socket_root"]; !ok {
		m["pun_socket_root"] = "/var/run/ondemand-nginx"
	}

	if _, ok := m["pun_max_retries"]; !ok {
		m["pun_max_retries"] = 5
	}

	if _, ok := m["oidc_remote_user_claim"]; !ok {
		m["oidc_remote_user_claim"] = "preferred_username"
	}

	if _, ok := m["oidc_scope"]; !ok {
		m["oidc_scope"] = "openid profile email"
	}

	if _, ok := m["oidc_session_inactivity_timeout"]; !ok {
		m["oidc_session_inactivity_timeout"] = 28800
	}

	if _, ok := m["oidc_session_max_duration"]; !ok {
		m["oidc_session_max_duration"] = 28800
	}

	if _, ok := m["oidc_state_max_number_of_cookies"]; !ok {
		m["oidc_state_max_number_of_cookies"] = "10 true"
	}

	// Convert map into portalConfig struct for later
	// processing into apache2 configuration templates.
	err = mapstructure.Decode(m, &p)
	if err != nil {
		return p, err
	}

	// Compute allowed_hosts before returning portal configuration.
	// Remove the need for obnoxious type checking and casting with `reflect`.
	allowedHosts, err := getAllowedHosts(p)
	if err != nil {
		return p, err
	}
	p.AllowedHosts = allowedHosts

	return p, nil
}

// Render the ood-portal.conf template.
func renderPortal(p portalConfig) (out string, err error) {
	t, err := template.New("ood-portal").Funcs(template.FuncMap{
		"analyticsEnabled": func(analytics analytics) bool {
			return !reflect.ValueOf(analytics).IsZero()
		},
		"chain": func(aliases []string, proxy string) []string {
			return append(aliases, proxy)
		},
		"escapeIPv4": func(ip string) string {
			return strings.ReplaceAll(ip, ".", "\\.")
		},
		"commaSeparate": func(hosts []string) string {
			return strings.Join(hosts, ",")
		},
	}).Parse(oodPortalTmpl)
	if err != nil {
		return out, err
	}

	// TODO: Need to set the auth default if Dex is
	// configured but auth is not.
	var buf bytes.Buffer
	err = t.Execute(&buf, p)
	if err != nil {
		return out, err
	}

	return buf.String(), nil
}

// Render the need-auth.conf template.
func renderNeedAuth(p portalConfig) (out string, err error) {
	t, err := template.New("need-auth").Parse(needAuthTmpl)
	if err != nil {
		return out, err
	}

	var buf bytes.Buffer
	err = t.Execute(&buf, p)
	if err != nil {
		return out, err
	}

	return buf.String(), nil
}

// Get the server name of the Open OnDemand portal.
//
// Returns the current FQDN of the host if no server_name
// is provided in the `ood_portal.yml` configuration file.
func getServerName(m map[string]any) (string, error) {
	if serverName, ok := m["servername"]; ok {
		return reflect.ValueOf(serverName).String(), nil
	} else if serverProxy, ok := m["proxy_server"]; ok {
		return reflect.ValueOf(serverProxy).String(), nil
	} else {
		// Need to perform some trickery here by calling
		// `/bin/hostname -f` as Go's `os.Hostname()` does not
		// provide the FQDN needed by Open OnDemand.
		var buf bytes.Buffer
		cmd := exec.Command("/bin/hostname", "--fqdn")
		cmd.Stdout = &buf
		err := cmd.Run()
		if err != nil {
			return "", err
		}

		fqdn := buf.String()
		return fqdn[:len(fqdn)-1], nil
	}
}

func getAllowedHosts(p portalConfig) ([]string, error) {
	// Create map that behaves like a set. This way
	// it is ensured that all allowed hosts are unique.
	hosts := make(map[string]bool)

	if p.ProxyServer != "" {
		hosts[p.ProxyServer] = true
	}

	if len(p.ServerAliases) > 0 {
		for _, alias := range p.ServerAliases {
			hosts[alias] = true
		}
	}

	if p.ServerName != "" {
		hosts[p.ServerName] = true
	} else {
		local, _ := getHostIPv4Addresses()
		for _, ip := range local {
			hosts[ip] = true
		}
	}

	allowedHosts := make([]string, 0, len(hosts))
	for host := range hosts {
		allowedHosts = append(allowedHosts, host)
	}
	return allowedHosts, nil
}

// Get available IPv4 addresses on the current host
// that are not loopback devices.
func getHostIPv4Addresses() ([]string, error) {
	var ips []string

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips, err
	}
	for _, addr := range addrs {
		if ip, ok := addr.(*net.IPNet); ok && !ip.IP.IsLoopback() {
			if ip.IP.To4() != nil {
				ips = append(ips, ip.IP.String())
			}
		}
	}

	return ips, nil
}
