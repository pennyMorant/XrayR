package api

import (
	"encoding/json"
	"regexp"

	"github.com/xtls/xray-core/infra/conf"
)

// Config API config
type Config struct {
	APIHost             string  `mapstructure:"ApiHost"`
	NodeID              int     `mapstructure:"NodeID"`
	Key                 string  `mapstructure:"ApiKey"`
	Timeout             int     `mapstructure:"Timeout"`
	SpeedLimit          float64 `mapstructure:"SpeedLimit"`
	DeviceLimit         int     `mapstructure:"DeviceLimit"`
	RuleListPath        string  `mapstructure:"RuleListPath"`
	DisableCustomConfig bool    `mapstructure:"DisableCustomConfig"`
}

// NodeStatus Node status
type NodeStatus struct {
	CPU    float64
	Mem    float64
	Disk   float64
	Uptime uint64
}

type NodeInfo struct {
	NodeType	      string
	NodeID            int
	Port              uint32
	SpeedLimit        uint64 // Bps
	TransportProtocol string
	FakeType          string
	Host              string
	Path              string
	EnableTLS         bool
	VlessFlow         string
	CypherMethod      string
	ServerKey         string
	ServiceName       string
	Header            json.RawMessage
	NameServerConfig  []*conf.NameServerConfig
}

type UserInfo struct {
	UID           int
	Email         string
	Passwd        string
	Port          uint32
	Method        string
	SpeedLimit    uint64 // Bps
	DeviceLimit   int
	UUID          string
}

type OnlineUser struct {
	UID int
	IP  string
}

type UserTraffic struct {
	UID      int
	Email    string
	Upload   int64
	Download int64
}

type ClientInfo struct {
	APIHost  string
	NodeID   int
	Key      string
	NodeType string
}

type DetectRule struct {
	ID      int
	Pattern *regexp.Regexp
}

type DetectResult struct {
	UID    int
	RuleID int
}
