package shuffle

import (
	"crypto/sha256"
	"fmt"
	"hash/crc32"
	"log"
	"strings"
	"sync"
	"time"

	gomemcache "github.com/bradfitz/gomemcache/memcache"
)

type shuffleMemcacheServer struct {
	address       string
	client        *gomemcache.Client
	disabledUntil time.Time
}

type shuffleMemcacheClient struct {
	mutex   sync.RWMutex
	servers []*shuffleMemcacheServer
}

func newShuffleMemcacheClient(addresses ...string) *shuffleMemcacheClient {
	client := &shuffleMemcacheClient{}
	for _, address := range addresses {
		address = strings.TrimSpace(address)
		if address == "" {
			continue
		}

		memcacheClient := gomemcache.New(address)
		memcacheClient.Timeout = 2 * time.Second
		client.servers = append(client.servers, &shuffleMemcacheServer{
			address: address,
			client:  memcacheClient,
		})
	}

	return client
}

func (client *shuffleMemcacheClient) availableServers(key string) []*shuffleMemcacheServer {
	client.mutex.RLock()
	defer client.mutex.RUnlock()

	if len(client.servers) == 0 {
		return nil
	}

	servers := make([]*shuffleMemcacheServer, 0, len(client.servers))
	now := time.Now()
	start := int(crc32.ChecksumIEEE([]byte(key)) % uint32(len(client.servers)))
	for offset := 0; offset < len(client.servers); offset++ {
		server := client.servers[(start+offset)%len(client.servers)]
		if !now.Before(server.disabledUntil) {
			servers = append(servers, server)
		}
	}

	return servers
}

func (client *shuffleMemcacheClient) disableServer(server *shuffleMemcacheServer, err error) {
	now := time.Now()
	client.mutex.Lock()
	wasDisabled := now.Before(server.disabledUntil)
	server.disabledUntil = now.Add(30 * time.Second)
	client.mutex.Unlock()

	if !wasDisabled {
		log.Printf("[WARNING] Disabling unavailable Memcached server %s for 30 seconds: %s", server.address, err)
	}
}

func (client *shuffleMemcacheClient) Get(key string) (*gomemcache.Item, error) {
	client.mutex.RLock()
	serverCount := len(client.servers)
	client.mutex.RUnlock()
	quorum := serverCount/2 + 1

	servers := client.availableServers(key)
	if len(servers) < quorum {
		return nil, gomemcache.ErrNoServers
	}

	type cacheValue struct {
		item  *gomemcache.Item
		count int
	}
	values := map[[sha256.Size]byte]cacheValue{}
	var lastErr error
	cacheMiss := false
	for _, server := range servers {
		item, err := server.client.Get(key)
		if err == nil {
			hash := sha256.Sum256(item.Value)
			value := values[hash]
			value.item = item
			value.count++
			values[hash] = value
			if value.count >= quorum {
				return item, nil
			}
			continue
		}
		if err == gomemcache.ErrCacheMiss {
			cacheMiss = true
			continue
		}
		if err == gomemcache.ErrMalformedKey {
			return nil, err
		}

		lastErr = err
		client.disableServer(server, err)
	}

	if len(values) > 0 {
		return nil, fmt.Errorf("memcached read quorum unavailable for key %s", key)
	}
	if cacheMiss {
		return nil, gomemcache.ErrCacheMiss
	}
	if lastErr != nil {
		return nil, lastErr
	}

	return nil, gomemcache.ErrNoServers
}

func (client *shuffleMemcacheClient) Set(item *gomemcache.Item) error {
	client.mutex.RLock()
	serverCount := len(client.servers)
	client.mutex.RUnlock()
	quorum := serverCount/2 + 1

	servers := client.availableServers(item.Key)
	if len(servers) < quorum {
		return gomemcache.ErrNoServers
	}

	var lastErr error
	successfulWrites := 0
	for _, server := range servers {
		err := server.client.Set(item)
		if err == nil {
			successfulWrites += 1
			continue
		}
		if err == gomemcache.ErrMalformedKey {
			return err
		}

		lastErr = err
		client.disableServer(server, err)
	}

	if successfulWrites >= quorum {
		return nil
	}
	if lastErr != nil {
		return fmt.Errorf("memcached write quorum unavailable: got %d of %d: %w", successfulWrites, quorum, lastErr)
	}

	return fmt.Errorf("memcached write quorum unavailable: got %d of %d", successfulWrites, quorum)
}

func (client *shuffleMemcacheClient) Add(item *gomemcache.Item) (bool, error) {
	client.mutex.RLock()
	serverCount := len(client.servers)
	if serverCount == 0 {
		client.mutex.RUnlock()
		return false, gomemcache.ErrNoServers
	}
	servers := append([]*shuffleMemcacheServer(nil), client.servers...)
	client.mutex.RUnlock()

	quorum := serverCount/2 + 1
	successes := 0
	successfulServers := []*shuffleMemcacheServer{}
	cleanupPartialClaim := func() {
		for _, server := range successfulServers {
			if err := server.client.Delete(item.Key); err != nil && err != gomemcache.ErrCacheMiss {
				client.disableServer(server, err)
			}
		}
	}
	start := int(crc32.ChecksumIEEE([]byte(item.Key)) % uint32(serverCount))
	var lastErr error
	for offset := 0; offset < serverCount; offset++ {
		server := servers[(start+offset)%serverCount]
		err := server.client.Add(item)
		if err == nil {
			successes++
			successfulServers = append(successfulServers, server)
			if successes >= quorum {
				return true, nil
			}
			continue
		}
		if err == gomemcache.ErrNotStored {
			cleanupPartialClaim()
			return false, nil
		}
		if err == gomemcache.ErrMalformedKey {
			return false, err
		}

		lastErr = err
		client.disableServer(server, err)
	}

	// A failed partial claim must not poison a replica until the TTL expires.
	cleanupPartialClaim()

	if lastErr != nil {
		return false, fmt.Errorf("memcached claim quorum unavailable: got %d of %d: %w", successes, quorum, lastErr)
	}
	return false, nil
}

func (client *shuffleMemcacheClient) CompareAndSwap(item *gomemcache.Item) error {
	servers := client.availableServers(item.Key)
	if len(servers) == 0 {
		return gomemcache.ErrNoServers
	}

	var lastErr error
	cacheMiss := false
	for _, server := range servers {
		err := server.client.CompareAndSwap(item)
		if err == nil {
			replicaItem := *item
			replicaItem.CasID = 0
			for _, replica := range servers {
				if replica == server {
					continue
				}
				if replicaErr := replica.client.Set(&replicaItem); replicaErr != nil {
					client.disableServer(replica, replicaErr)
				}
			}

			return nil
		}
		if err == gomemcache.ErrCASConflict {
			return err
		}
		if err == gomemcache.ErrCacheMiss {
			cacheMiss = true
			continue
		}
		if err == gomemcache.ErrMalformedKey {
			return err
		}

		lastErr = err
		client.disableServer(server, err)
	}

	if cacheMiss {
		return gomemcache.ErrCacheMiss
	}
	if lastErr != nil {
		return lastErr
	}

	return gomemcache.ErrNoServers
}

// Increment mirrors gomemcache's Increment across every available server, so
// replicas stay in sync. The first successful value is returned.
func (client *shuffleMemcacheClient) Increment(key string, delta uint64) (uint64, error) {
	servers := client.availableServers(key)
	if len(servers) == 0 {
		return 0, gomemcache.ErrNoServers
	}

	var lastErr error
	cacheMiss := false
	incremented := false
	newValue := uint64(0)
	for _, server := range servers {
		value, err := server.client.Increment(key, delta)
		if err == nil {
			if !incremented {
				newValue = value
				incremented = true
			}

			continue
		}
		if err == gomemcache.ErrCacheMiss {
			cacheMiss = true
			continue
		}
		if err == gomemcache.ErrMalformedKey {
			return 0, err
		}

		lastErr = err
		client.disableServer(server, err)
	}

	if incremented {
		return newValue, nil
	}
	if cacheMiss {
		return 0, gomemcache.ErrCacheMiss
	}
	if lastErr != nil {
		return 0, lastErr
	}

	return 0, gomemcache.ErrNoServers
}

// Touch resets the expiration on every available server holding the key.
func (client *shuffleMemcacheClient) Touch(key string, seconds int32) error {
	servers := client.availableServers(key)
	if len(servers) == 0 {
		return gomemcache.ErrNoServers
	}

	var lastErr error
	cacheMiss := false
	touched := false
	for _, server := range servers {
		err := server.client.Touch(key, seconds)
		if err == nil {
			touched = true
			continue
		}
		if err == gomemcache.ErrCacheMiss {
			cacheMiss = true
			continue
		}
		if err == gomemcache.ErrMalformedKey {
			return err
		}

		lastErr = err
		client.disableServer(server, err)
	}

	if touched {
		return nil
	}
	if cacheMiss {
		return gomemcache.ErrCacheMiss
	}
	if lastErr != nil {
		return lastErr
	}

	return gomemcache.ErrNoServers
}

func (client *shuffleMemcacheClient) Delete(key string) error {
	client.mutex.RLock()
	serverCount := len(client.servers)
	client.mutex.RUnlock()
	quorum := serverCount/2 + 1

	servers := client.availableServers(key)
	if len(servers) < quorum {
		return gomemcache.ErrNoServers
	}

	var lastErr error
	cacheMiss := false
	confirmedAbsent := 0
	for _, server := range servers {
		err := server.client.Delete(key)
		if err == nil {
			confirmedAbsent++
			continue
		}
		if err == gomemcache.ErrCacheMiss {
			cacheMiss = true
			confirmedAbsent++
			continue
		}
		if err == gomemcache.ErrMalformedKey {
			return err
		}

		lastErr = err
		client.disableServer(server, err)
	}

	if confirmedAbsent >= quorum {
		return nil
	}
	if lastErr != nil {
		return fmt.Errorf("memcached delete quorum unavailable: %w", lastErr)
	}
	if cacheMiss {
		return gomemcache.ErrCacheMiss
	}

	return fmt.Errorf("memcached delete quorum unavailable")
}
