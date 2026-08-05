package shuffle

import (
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
	servers := client.availableServers(key)
	if len(servers) == 0 {
		return nil, gomemcache.ErrNoServers
	}

	var lastErr error
	cacheMiss := false
	for _, server := range servers {
		item, err := server.client.Get(key)
		if err == nil {
			return item, nil
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

	if cacheMiss {
		return nil, gomemcache.ErrCacheMiss
	}
	if lastErr != nil {
		return nil, lastErr
	}

	return nil, gomemcache.ErrNoServers
}

func (client *shuffleMemcacheClient) Set(item *gomemcache.Item) error {
	servers := client.availableServers(item.Key)
	if len(servers) == 0 {
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

	if successfulWrites > 0 {
		return nil
	}
	if lastErr != nil {
		return lastErr
	}

	return gomemcache.ErrNoServers
}

func (client *shuffleMemcacheClient) Add(item *gomemcache.Item) (bool, error) {
	client.mutex.RLock()
	if len(client.servers) == 0 {
		client.mutex.RUnlock()
		return false, gomemcache.ErrNoServers
	}

	// Atomic claims must always use the same server. Failing over here could
	// allow two callers to acquire the same key on different servers.
	server := client.servers[int(crc32.ChecksumIEEE([]byte(item.Key))%uint32(len(client.servers)))]
	client.mutex.RUnlock()

	err := server.client.Add(item)
	if err == nil {
		return true, nil
	}
	if err == gomemcache.ErrNotStored {
		return false, nil
	}
	if err != gomemcache.ErrMalformedKey {
		client.disableServer(server, err)
	}

	return false, err
}

func (client *shuffleMemcacheClient) Delete(key string) error {
	servers := client.availableServers(key)
	if len(servers) == 0 {
		return gomemcache.ErrNoServers
	}

	var lastErr error
	cacheMiss := false
	deleted := false
	for _, server := range servers {
		err := server.client.Delete(key)
		if err == nil {
			deleted = true
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

	if deleted {
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
