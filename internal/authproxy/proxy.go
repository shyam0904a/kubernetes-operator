package authproxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/go-logr/logr"
)

const (
	// ModeAuth enables identity-based impersonation using NetBird peer info
	ModeAuth = "auth"
	// ModeNoAuth passes requests through without impersonation
	ModeNoAuth = "noauth"
)

// PeerIdentityLookup is a function that returns the identity info for a peer by IP
type PeerIdentityLookup func(ip string) (userId string, groups []string, ok bool)

// Config holds the auth proxy configuration
type Config struct {
	// ListenAddr is the address to listen on (e.g., ":6443")
	ListenAddr string
	// Mode is either "auth" or "noauth"
	Mode string
	// K8sAPIServer is the URL of the Kubernetes API server
	K8sAPIServer string
	// TLSCertFile is the path to the TLS certificate file
	TLSCertFile string
	// TLSKeyFile is the path to the TLS key file
	TLSKeyFile string
	// Logger for logging
	Logger logr.Logger
	// PeerLookup is the function to look up peer identity by IP
	PeerLookup PeerIdentityLookup
}

// Server is the API server auth proxy
type Server struct {
	config     Config
	httpServer *http.Server
	proxy      *httputil.ReverseProxy
	logger     logr.Logger
}

// New creates a new auth proxy server
func New(config Config) (*Server, error) {
	if config.Mode != ModeAuth && config.Mode != ModeNoAuth {
		return nil, fmt.Errorf("invalid mode: %s, must be 'auth' or 'noauth'", config.Mode)
	}

	targetURL, err := url.Parse(config.K8sAPIServer)
	if err != nil {
		return nil, fmt.Errorf("invalid k8s api server url: %w", err)
	}

	s := &Server{
		config: config,
		logger: config.Logger.WithName("authproxy"),
	}

	// Create reverse proxy
	s.proxy = &httputil.ReverseProxy{
		Director: s.director(targetURL),
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// Use the service account token for auth to API server
				InsecureSkipVerify: true, // In production, load the CA cert
			},
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		ErrorHandler: s.errorHandler,
	}

	return s, nil
}

// director modifies the request before forwarding
func (s *Server) director(target *url.URL) func(*http.Request) {
	return func(req *http.Request) {
		// Set target
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host

		// Remove any existing impersonation headers (security)
		for key := range req.Header {
			if strings.HasPrefix(strings.ToLower(key), "impersonate-") {
				req.Header.Del(key)
			}
		}

		// In auth mode, add impersonation headers based on peer identity
		if s.config.Mode == ModeAuth && s.config.PeerLookup != nil {
			clientIP := extractClientIP(req.RemoteAddr)
			userId, groups, ok := s.config.PeerLookup(clientIP)
			if ok {
				s.logger.V(1).Info("impersonating user", "ip", clientIP, "user", userId, "groups", groups)
				req.Header.Set("Impersonate-User", userId)
				for _, group := range groups {
					req.Header.Add("Impersonate-Group", group)
				}
			} else {
				s.logger.Info("peer identity not found, denying request", "ip", clientIP)
				// We'll handle this in the error handler by checking if impersonation headers are set
			}
		}

		// Log the request
		s.logger.V(1).Info("proxying request",
			"method", req.Method,
			"path", req.URL.Path,
			"remote", req.RemoteAddr,
		)
	}
}

// errorHandler handles proxy errors
func (s *Server) errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	s.logger.Error(err, "proxy error", "path", r.URL.Path)
	http.Error(w, "proxy error", http.StatusBadGateway)
}

// ServeHTTP implements http.Handler
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// In auth mode, check if we have a valid peer identity
	if s.config.Mode == ModeAuth && s.config.PeerLookup != nil {
		clientIP := extractClientIP(r.RemoteAddr)
		_, _, ok := s.config.PeerLookup(clientIP)
		if !ok {
			s.logger.Info("unauthorized: peer identity not found", "ip", clientIP)
			http.Error(w, "unauthorized: peer not recognized", http.StatusUnauthorized)
			return
		}
	}

	s.proxy.ServeHTTP(w, r)
}

// Start starts the auth proxy server
func (s *Server) Start(ctx context.Context) error {
	s.httpServer = &http.Server{
		Addr:    s.config.ListenAddr,
		Handler: s,
	}

	s.logger.Info("starting auth proxy",
		"addr", s.config.ListenAddr,
		"mode", s.config.Mode,
		"target", s.config.K8sAPIServer,
	)

	errCh := make(chan error, 1)

	go func() {
		var err error
		if s.config.TLSCertFile != "" && s.config.TLSKeyFile != "" {
			err = s.httpServer.ListenAndServeTLS(s.config.TLSCertFile, s.config.TLSKeyFile)
		} else {
			err = s.httpServer.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(shutdownCtx)
	}
}

// extractClientIP extracts the client IP from RemoteAddr
func extractClientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

