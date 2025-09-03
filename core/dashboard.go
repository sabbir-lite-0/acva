package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sabbir-lite-0/acva/utils"
)

type Dashboard struct {
	logger     *utils.Logger
	clients    map[*websocket.Conn]bool
	broadcast  chan DashboardMessage
	upgrader   websocket.Upgrader
	clientsMux sync.Mutex
}

type DashboardMessage struct {
	Type    string      `json:"type"`
	Payload interface{} `json:"payload"`
}

func NewDashboard(logger *utils.Logger) *Dashboard {
	return &Dashboard{
		logger:    logger,
		clients:   make(map[*websocket.Conn]bool),
		broadcast: make(chan DashboardMessage),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
	}
}

func (d *Dashboard) HandleConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := d.upgrader.Upgrade(w, r, nil)
	if err != nil {
		d.logger.Error("WebSocket upgrade failed: %v", err)
		return
	}
	defer ws.Close()

	// Register client
	d.clientsMux.Lock()
	d.clients[ws] = true
	d.clientsMux.Unlock()

	d.logger.Info("New dashboard client connected")

	for {
		var msg map[string]interface{}
		err := ws.ReadJSON(&msg)
		if err != nil {
			d.logger.Debug("Client disconnected: %v", err)
			d.clientsMux.Lock()
			delete(d.clients, ws)
			d.clientsMux.Unlock()
			break
		}

		d.logger.Debug("Received message from dashboard: %v", msg)
	}
}

func (d *Dashboard) BroadcastUpdate(message DashboardMessage) {
	d.clientsMux.Lock()
	defer d.clientsMux.Unlock()

	if len(d.clients) == 0 {
		return
	}

	messageJSON, err := json.Marshal(message)
	if err != nil {
		d.logger.Error("Failed to marshal message: %v", err)
		return
	}

	for client := range d.clients {
		err := client.WriteMessage(websocket.TextMessage, messageJSON)
		if err != nil {
			d.logger.Debug("Failed to send message to client: %v", err)
			client.Close()
			delete(d.clients, client)
		}
	}
}

func (d *Dashboard) Start() {
	go d.handleBroadcasts()
}

func (d *Dashboard) handleBroadcasts() {
	for {
		select {
		case msg := <-d.broadcast:
			d.BroadcastUpdate(msg)
		}
	}
}

func (d *Dashboard) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"connected_clients": len(d.clients),
		"timestamp":         time.Now().Format(time.RFC3339),
	}
}
