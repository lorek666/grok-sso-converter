package main

import (
	"encoding/json"
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"gopkg.in/yaml.v3"
)

const (
	pluginID         = "sso-import"
	convertRouteRel  = "/plugins/sso-import/convert"
	statusRouteRel   = "/plugins/sso-import/status"
	resourcePageRel  = "/import"
	convertRoutePath = "/v0/management" + convertRouteRel
	statusRoutePath  = "/v0/management" + statusRouteRel
	resourcePagePath = "/v0/resource/plugins/" + pluginID + resourcePageRel
)

// imp 是插件全局实例：register/reconfigure 时更新配置，handle 时使用。
var imp = newHandler(hostAuthSave)

// handleMethod 是宿主 → 插件的唯一分发入口（C ABI 之上的 JSON RPC）。
func handleMethod(method string, request []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		return handleLifecycle(method, request)
	case pluginabi.MethodManagementRegister:
		return managementRegistration()
	case pluginabi.MethodManagementHandle:
		return handleManagementCall(request)
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method), nil
	}
}

// pluginConfig 是 plugins.configs.sso-import 下宿主保留的自有字段；宿主
// 解析的 enabled/priority 不透传。
type pluginConfig struct {
	Proxy string `yaml:"proxy"`
}

func handleLifecycle(method string, request []byte) ([]byte, error) {
	var req struct {
		ConfigYAML []byte `json:"config_yaml"`
	}
	if len(request) > 0 {
		if err := json.Unmarshal(request, &req); err != nil {
			return nil, err
		}
	}
	var cfg pluginConfig
	if len(req.ConfigYAML) > 0 {
		if err := yaml.Unmarshal(req.ConfigYAML, &cfg); err != nil {
			// 配置不合法不阻断加载：按无代理继续，错误在转换时暴露。
			cfg.Proxy = ""
		}
	}
	imp.setConfig(cfg.Proxy)
	meta := pluginapi.Metadata{
		Name:    "SSO Import",
		Version: "1.0.0",
		Author:  "s2sso",
		// 宿主 validPlugin 要求非空；指向本插件源码仓库。
		GitHubRepository: "https://github.com/lorek666/grok-sso-converter",
		ConfigFields: []pluginapi.ConfigField{{
			Name:        "proxy",
			Type:        pluginapi.ConfigFieldTypeString,
			Description: "Optional outbound proxy URL passed to the sso fingerprint client.",
		}},
	}
	return okEnvelope(registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata:      meta,
		Capabilities:  registrationCapabilities{ManagementAPI: true},
	})
}

type registration struct {
	SchemaVersion uint32                   `json:"schema_version"`
	Metadata      pluginapi.Metadata       `json:"metadata"`
	Capabilities  registrationCapabilities `json:"capabilities"`
}

type registrationCapabilities struct {
	ManagementAPI bool `json:"management_api"`
}

func managementRegistration() ([]byte, error) {
	return okEnvelope(pluginapi.ManagementRegistrationResponse{
		Routes: []pluginapi.ManagementRoute{{
			Method: http.MethodPost,
			Path:   convertRouteRel,
		}, {
			Method: http.MethodGet,
			Path:   statusRouteRel,
		}},
		Resources: []pluginapi.ResourceRoute{{
			Path:        resourcePageRel,
			Menu:        "SSO 导入",
			Description: "贴 sso cookie 一键转换并导入 xai 凭证。",
		}},
	})
}

func handleManagementCall(request []byte) ([]byte, error) {
	var req pluginapi.ManagementRequest
	if len(request) > 0 {
		if err := json.Unmarshal(request, &req); err != nil {
			return nil, err
		}
	}
	return okEnvelope(imp.handle(req))
}
