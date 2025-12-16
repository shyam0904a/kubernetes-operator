package authproxy

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"github.com/netbirdio/netbird/client/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// PeerStore maintains a cache of peer identity information from the NetBird daemon
type PeerStore struct {
	daemonAddr  string
	refreshRate time.Duration
	logger      logr.Logger
	mu          sync.RWMutex
	peersByIP   map[string]*PeerInfo
	stopCh      chan struct{}
}

// PeerInfo contains identity information for a peer
type PeerInfo struct {
	IP     string
	FQDN   string
	UserId string
	Groups []string
}

// NewPeerStore creates a new peer store
func NewPeerStore(daemonAddr string, refreshRate time.Duration, logger logr.Logger) *PeerStore {
	return &PeerStore{
		daemonAddr:  daemonAddr,
		refreshRate: refreshRate,
		logger:      logger.WithName("peerstore"),
		peersByIP:   make(map[string]*PeerInfo),
		stopCh:      make(chan struct{}),
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

// dialDaemon connects to the NetBird daemon via gRPC
func (ps *PeerStore) dialDaemon(ctx context.Context) (*grpc.ClientConn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Handle both unix socket and tcp addresses
	// Format: unix:///var/run/netbird.sock or tcp://host:port
	addr := strings.TrimPrefix(ps.daemonAddr, "tcp://")

	return grpc.DialContext(
		dialCtx,
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
}

// refresh fetches the latest peer status from the NetBird daemon via gRPC
func (ps *PeerStore) refresh(ctx context.Context) error {
	conn, err := ps.dialDaemon(ctx)
	if err != nil {
		ps.logger.V(1).Info("failed to connect to netbird daemon", "error", err)
		return nil // Not a hard error - daemon might not be ready
	}
	defer conn.Close()

	client := proto.NewDaemonServiceClient(conn)

	resp, err := client.Status(ctx, &proto.StatusRequest{
		GetFullPeerStatus: true,
	})
	if err != nil {
		ps.logger.V(1).Info("failed to get status from daemon", "error", err)
		return nil
	}

	fullStatus := resp.GetFullStatus()
	if fullStatus == nil {
		ps.logger.V(1).Info("daemon returned nil fullStatus")
		return nil
	}

	newPeers := make(map[string]*PeerInfo)
	for _, peer := range fullStatus.GetPeers() {
		ip := peer.GetIP()
		if ip == "" {
			continue
		}
		// Strip /32 suffix if present
		ip = strings.TrimSuffix(ip, "/32")

		newPeers[ip] = &PeerInfo{
			IP:     ip,
			FQDN:   peer.GetFqdn(),
			UserId: peer.GetUserId(),
			Groups: peer.GetGroups(),
		}
		ps.logger.V(2).Info("found peer", "ip", ip, "userId", peer.GetUserId(), "groups", peer.GetGroups())
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

// GetPeerCount returns the number of peers in the cache
func (ps *PeerStore) GetPeerCount() int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return len(ps.peersByIP)
}
