package types

type OpenClawConfig struct {
	Gateway   GatewayConfig            `json:"gateway"`
	Agents    AgentsConfig             `json:"agents"`
	Skills    SkillsConfig             `json:"skills"`
	Logging   LoggingConfig            `json:"logging"`
	Discovery DiscoveryConfig          `json:"discovery"`
	Tools     ToolsConfig              `json:"tools"`
	Meta      MetaConfig               `json:"meta"`
	Channels  map[string]ChannelConfig `json:"channels"`
	Models    ModelsConfig             `json:"models"`
	Session   SessionConfig            `json:"session"`
	Acp       AcpConfig                `json:"acp"`
	Sandbox   SandboxConfig            `json:"sandbox"`
}

type GatewayConfig struct {
	Mode                string           `json:"mode"`
	Bind                string           `json:"bind"`
	Auth                GatewayAuth      `json:"auth"`
	ControlUi           GatewayControlUi `json:"controlUi"`
	Tailscale           GatewayTailscale `json:"tailscale"`
	TrustedProxies      []string         `json:"trustedProxies"`
	AllowRealIpFallback bool             `json:"allowRealIpFallback"`
}

type GatewayAuth struct {
	Mode         string                `json:"mode"`
	Token        string                `json:"token"`
	Password     string                `json:"password"`
	TrustedProxy *GatewayTrustedProxy  `json:"trustedProxy"`
	RateLimit    *GatewayAuthRateLimit `json:"rateLimit"`
}

type GatewayControlUi struct {
	Enabled                                  bool     `json:"enabled"`
	AllowedOrigins                           []string `json:"allowedOrigins"`
	DangerouslyAllowHostHeaderOriginFallback bool     `json:"dangerouslyAllowHostHeaderOriginFallback"`
	DangerouslyDisableDeviceAuth             bool     `json:"dangerouslyDisableDeviceAuth"`
	AllowInsecureAuth                        bool     `json:"allowInsecureAuth"`
}

type GatewayTailscale struct {
	Mode        string `json:"mode"`
	ResetOnExit bool   `json:"resetOnExit"`
}

type GatewayTrustedProxy struct {
	UserHeader      string   `json:"userHeader"`
	RequiredHeaders []string `json:"requiredHeaders"`
	AllowUsers      []string `json:"allowUsers"`
}

type GatewayAuthRateLimit struct {
	MaxAttempts int `json:"maxAttempts"`
	WindowMs    int `json:"windowMs"`
	LockoutMs   int `json:"lockoutMs"`
}

type AgentsConfig struct {
	Defaults AgentDefaults `json:"defaults"`
}

type AgentDefaults struct {
	Workspace     string         `json:"workspace"`
	MaxConcurrent int            `json:"maxConcurrent"`
	Subagents     SubagentLimits `json:"subagents"`
}

type SubagentLimits struct {
	MaxConcurrent int `json:"maxConcurrent"`
}

type SkillsConfig struct {
	AllowBundled []string                    `json:"allowBundled"`
	Entries      map[string]SkillEntryConfig `json:"entries"`
}

type SkillEntryConfig struct {
	Enabled bool              `json:"enabled"`
	Env     map[string]string `json:"env"`
}

type LoggingConfig struct {
	RedactSensitive string `json:"redactSensitive"`
}

type DiscoveryConfig struct {
	Mdns MdnsConfig `json:"mdns"`
}

type MdnsConfig struct {
	Mode string `json:"mode"`
}

type ToolsConfig struct {
	Elevated ElevatedConfig `json:"elevated"`
}

type ElevatedConfig struct {
	Enabled   bool                   `json:"enabled"`
	AllowFrom map[string]interface{} `json:"allowFrom"`
}

type MetaConfig struct {
	LastTouchedVersion string `json:"lastTouchedVersion"`
	LastTouchedAt      string `json:"lastTouchedAt"`
}

type SessionConfig struct {
	DmScope string `json:"dmScope"`
}

type AcpConfig struct {
	AutoApprove string `json:"autoApprove"`
}

type SandboxConfig struct {
	Mode string `json:"mode"`
}

type ChannelConfig struct {
	LoginMode   string            `json:"loginMode"`
	Environment string            `json:"environment"`
	QClaw       *QClawCredentials `json:"qclaw,omitempty"`
	WorkBuddy   map[string]any    `json:"workbuddy,omitempty"`
	Accounts    map[string]any    `json:"accounts,omitempty"`
	DmPolicy    string            `json:"dmPolicy"`
	GroupPolicy string            `json:"groupPolicy"`
	AllowFrom   []string          `json:"allowFrom"`
	AllowList   []string          `json:"allowlist"`
}

type QClawCredentials struct {
	JwtToken     string `json:"jwtToken"`
	ChannelToken string `json:"channelToken"`
	ApiKey       string `json:"apiKey"`
	Guid         string `json:"guid"`
	UserId       string `json:"userId"`
	WsUrl        string `json:"wsUrl"`
}

type ModelsConfig struct {
	Providers map[string]ModelProviderConfig `json:"providers"`
}

type ModelProviderConfig struct {
	ApiKey  string `json:"apiKey"`
	BaseUrl string `json:"baseUrl"`
}
