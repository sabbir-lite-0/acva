package core

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sabbir-lite-0/acva/utils"
	"github.com/redis/go-redis/v9"
)

type ClusterManager struct {
	redisClient *redis.Client
	logger      *utils.Logger
	config      utils.Config
}

func NewClusterManager(redisURL string, logger *utils.Logger, config utils.Config) *ClusterManager {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		logger.Error("Failed to parse Redis URL: %v", err)
		return nil
	}

	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	_, err = client.Ping(ctx).Result()
	if err != nil {
		logger.Error("Failed to connect to Redis: %v", err)
		return nil
	}

	return &ClusterManager{
		redisClient: client,
		logger:      logger,
		config:      config,
	}
}

func (c *ClusterManager) DistributeScan(target string, scanConfig ScanConfig) (string, error) {
	scanID := generateUUID()
	
	scanConfig.ScanID = scanID
	scanConfig.StartedAt = time.Now().Format(time.RFC3339)
	scanConfig.Target = target

	configJSON, err := json.Marshal(scanConfig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal scan config: %v", err)
	}

	ctx := context.Background()
	
	// Push scan to queue
	err = c.redisClient.RPush(ctx, "acva:scan:queue", configJSON).Err()
	if err != nil {
		return "", fmt.Errorf("failed to push scan to queue: %v", err)
	}

	// Store scan metadata
	scanMetadata := map[string]interface{}{
		"id":        scanID,
		"target":    target,
		"status":    "queued",
		"created_at": time.Now().Format(time.RFC3339),
		"config":    scanConfig,
	}

	metadataJSON, err := json.Marshal(scanMetadata)
	if err != nil {
		return "", fmt.Errorf("failed to marshal scan metadata: %v", err)
	}

	err = c.redisClient.Set(ctx, fmt.Sprintf("acva:scan:%s", scanID), metadataJSON, 24*time.Hour).Err()
	if err != nil {
		return "", fmt.Errorf("failed to store scan metadata: %v", err)
	}

	c.logger.Info("Distributed scan %s for target: %s", scanID, target)
	return scanID, nil
}

func (c *ClusterManager) GetScanStatus(scanID string) (map[string]interface{}, error) {
	ctx := context.Background()
	
	data, err := c.redisClient.Get(ctx, fmt.Sprintf("acva:scan:%s", scanID)).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get scan status: %v", err)
	}

	var status map[string]interface{}
	err = json.Unmarshal([]byte(data), &status)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal scan status: %v", err)
	}

	return status, nil
}

func (c *ClusterManager) RegisterWorker(workerID, workerAddr string) error {
	ctx := context.Background()
	
	workerInfo := map[string]interface{}{
		"id":         workerID,
		"address":    workerAddr,
		"last_seen":  time.Now().Format(time.RFC3339),
		"status":     "active",
	}

	infoJSON, err := json.Marshal(workerInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal worker info: %v", err)
	}

	// Store worker info with expiration
	err = c.redisClient.Set(ctx, fmt.Sprintf("acva:worker:%s", workerID), infoJSON, 30*time.Second).Err()
	if err != nil {
		return fmt.Errorf("failed to register worker: %v", err)
	}

	// Add to active workers set
	err = c.redisClient.ZAdd(ctx, "acva:workers", redis.Z{
		Score:  float64(time.Now().Unix()),
		Member: workerID,
	}).Err()
	if err != nil {
		return fmt.Errorf("failed to add worker to set: %v", err)
	}

	c.logger.Info("Registered worker: %s (%s)", workerID, workerAddr)
	return nil
}

func (c *ClusterManager) GetWorkers() ([]map[string]interface{}, error) {
	ctx := context.Background()
	
	// Remove stale workers (not seen in last 30 seconds)
	oldest := time.Now().Add(-30 * time.Second).Unix()
	c.redisClient.ZRemRangeByScore(ctx, "acva:workers", "0", fmt.Sprintf("%d", oldest))

	workerIDs, err := c.redisClient.ZRange(ctx, "acva:workers", 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get worker IDs: %v", err)
	}

	var workers []map[string]interface{}
	for _, workerID := range workerIDs {
		data, err := c.redisClient.Get(ctx, fmt.Sprintf("acva:worker:%s", workerID)).Result()
		if err != nil {
			c.logger.Debug("Failed to get worker info for %s: %v", workerID, err)
			continue
		}

		var workerInfo map[string]interface{}
		err = json.Unmarshal([]byte(data), &workerInfo)
		if err != nil {
			c.logger.Debug("Failed to unmarshal worker info for %s: %v", workerID, err)
			continue
		}

		workers = append(workers, workerInfo)
	}

	return workers, nil
}

func (c *ClusterManager) UpdateScanStatus(scanID string, status map[string]interface{}) error {
	ctx := context.Background()
	
	statusJSON, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("failed to marshal scan status: %v", err)
	}

	err = c.redisClient.Set(ctx, fmt.Sprintf("acva:scan:%s", scanID), statusJSON, 24*time.Hour).Err()
	if err != nil {
		return fmt.Errorf("failed to update scan status: %v", err)
	}

	return nil
}

func (c *ClusterManager) Close() error {
	return c.redisClient.Close()
}
