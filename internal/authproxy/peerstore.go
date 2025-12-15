package authproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-logr/logr"
)

// PeerStore maintains a cache of peer identity information from the NetBird daemon
type PeerStore struct {
	daemonAddr  string
	refreshRate time.Duration
	logger      logr.Logger
	mu          sync.RWMutex
	peersByIP   map[string]*PeerInfo
	stopCh      chan struct{}
	httpClient  *http.Client
}

// PeerInfo contains identity information for a peer
type PeerInfo struct {
	IP     string
	FQDN   string
	UserId string
	Groups []string
}

// peerStatusResponse matches the daemon status JSON response
type peerStatusResponse struct {
	Status     string `json:"status"`
	FullStatus struct {
		Peers []struct {
			IP     string   `json:"IP"`
			FQDN   string   `json:"fqdn"`
			Groups []string `json:"groups"`
			UserId string   `json:"userId"`
		} `json:"peers"`
	} `json:"fullStatus"`
}

// NewPeerStore creates a new peer store
func NewPeerStore(daemonAddr string, refreshRate time.Duration, logger logr.Logger) *PeerStore {
	transport := &http.Transport{}

	// If it's a unix socket address, configure for Unix sockets
	if len(daemonAddr) > 0 && daemonAddr[0] == '/' {
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("unix", daemonAddr)
		}
	}

	return &PeerStore{
		daemonAddr:  daemonAddr,
		refreshRate: refreshRate,
		logger:      logger.WithName("peerstore"),
		peersByIP:   make(map[string]*PeerInfo),
		stopCh:      make(chan struct{}),
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
	}
}

// Start begins the background refresh loop
func (ps *PeerStore) Start(ctx context.Context) error {
	ps.logger.Info("starting peer store", "daemon", ps.daemonAddr, "refresh", ps.refreshRate)

	// Initial refresh
	if err := ps.refresh(ctx); err != nil {
		ps.logger.Error(err, "initial peer refresh failed")
	}

	go ps.refreshLoop(ctx)
	return nil
}

// Stop stops the background refresh loop
func (ps *PeerStore) Stop() {
	close(ps.stopCh)
}

// LookupByIP returns peer identity information by IP address
func (ps *PeerStore) LookupByIP(ip string) (userId string, groups []string, ok bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	peer, ok := ps.peersByIP[ip]
	if !ok {
		return "", nil, false
	}
	return peer.UserId, peer.Groups, true
}

// refreshLoop periodically refreshes the peer cache
func (ps *PeerStore) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(ps.refreshRate)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ps.stopCh:
			return
		case <-ticker.C:
			if err := ps.refresh(ctx); err != nil {
				ps.logger.Error(err, "peer refresh failed")
			}
		}
	}
}

// refresh fetches the latest peer status from the NetBird daemon
// This uses a REST-like interface that the daemon may expose
func (ps *PeerStore) refresh(ctx context.Context) error {
	// For now, we'll use a placeholder approach
	// In production, this would call the netbird daemon's status API
	// The actual implementation depends on how the daemon exposes peer info

	// If using Unix socket HTTP
	req, err := http.NewRequestWithContext(ctx, "GET", "http://localhost/api/status?fullPeerStatus=true", nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := ps.httpClient.Do(req)
	if err != nil {
		// Not a hard error - daemon might not be ready
		ps.logger.V(1).Info("failed to fetch peer status", "error", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	var statusResp peerStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&statusResp); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	newPeers := make(map[string]*PeerInfo)
	for _, peer := range statusResp.FullStatus.Peers {
		if peer.IP == "" {
			continue
		}
		newPeers[peer.IP] = &PeerInfo{
			IP:     peer.IP,
			FQDN:   peer.FQDN,
			UserId: peer.UserId,
			Groups: peer.Groups,
		}
	}

	ps.mu.Lock()
	ps.peersByIP = newPeers
	ps.mu.Unlock()

	ps.logger.V(1).Info("refreshed peer cache", "count", len(newPeers))
	return nil
}

// AddPeer manually adds a peer to the store (for testing or static configuration)
func (ps *PeerStore) AddPeer(ip, fqdn, userId string, groups []string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.peersByIP[ip] = &PeerInfo{
		IP:     ip,
		FQDN:   fqdn,
		UserId: userId,
		Groups: groups,
	}
}
