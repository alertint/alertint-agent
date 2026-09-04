{{/*
Expand the name of the chart.
*/}}
{{- define "alertint-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "alertint-agent.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart name and version as used by the chart label.
*/}}
{{- define "alertint-agent.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "alertint-agent.labels" -}}
helm.sh/chart: {{ include "alertint-agent.chart" . }}
{{ include "alertint-agent.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "alertint-agent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "alertint-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Name of the ServiceAccount to use.
*/}}
{{- define "alertint-agent.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "alertint-agent.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Name of the Secret providing *_env values, whether created by this chart or
supplied externally.
*/}}
{{- define "alertint-agent.secretName" -}}
{{- if .Values.secret.existingSecret }}
{{- .Values.secret.existingSecret }}
{{- else }}
{{- include "alertint-agent.fullname" . }}
{{- end }}
{{- end }}

{{/*
Fails the render with a clear message if the Secret modes are misconfigured:
secret.create and secret.existingSecret are mutually exclusive, and exactly
one of them (or an explicit secret.enabled: false opt-out) must be chosen —
there is no implicit default that silently references a Secret that was
never created.
*/}}
{{- define "alertint-agent.validateSecret" -}}
{{- if and .Values.secret.create .Values.secret.existingSecret }}
{{- fail "secret.create and secret.existingSecret are mutually exclusive — set only one." }}
{{- end }}
{{- if and .Values.secret.enabled (not .Values.secret.create) (not .Values.secret.existingSecret) }}
{{- fail "No Secret configured: set secret.create=true (with secret.data), or secret.existingSecret to a Secret you manage yourself, or secret.enabled=false to deliberately opt out of the built-in Secret (e.g. if extraEnv/extraEnvFrom cover everything config.* references)." }}
{{- end }}
{{- end }}

{{/*
Name of the ConfigMap mounted at /etc/alertint, whether created by this
chart or supplied externally.
*/}}
{{- define "alertint-agent.configMapName" -}}
{{- if .Values.existingConfigMap }}
{{- .Values.existingConfigMap }}
{{- else }}
{{- include "alertint-agent.fullname" . }}
{{- end }}
{{- end }}

{{/*
Effective MCP enablement, mirroring the app's own presence-based config.mcp
logic (internal/config: MCPConfig.Enabled is a *bool — nil means "on when
the env var named by token_env holds a token") as closely as a chart
rendered ahead of time can:
  "enabled"  - config.mcp.enabled is explicitly true, OR it's unset and
               secret.create provides a non-empty value for token_env.
  "disabled" - config.mcp.enabled is explicitly false, OR it's unset with
               no Secret able to supply token_env at all.
  "unknown"  - config.mcp.enabled is unset and secret.existingSecret is
               used — the chart cannot see whether that Secret actually
               carries a value for token_env.
Skipped entirely (using configOverride/existingConfigMap instead of
config.mcp): treated as "unknown", for the same reason as existingSecret.
*/}}
{{- define "alertint-agent.mcpState" -}}
{{- if or .Values.configOverride .Values.existingConfigMap -}}
unknown
{{- else -}}
{{- $mcp := .Values.config.mcp | default dict -}}
{{- if hasKey $mcp "enabled" -}}
{{- if $mcp.enabled }}enabled{{ else }}disabled{{ end -}}
{{- else if and .Values.secret.create $mcp.token_env (index .Values.secret.data $mcp.token_env) -}}
enabled
{{- else if .Values.secret.existingSecret -}}
unknown
{{- else -}}
disabled
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Name of the PersistentVolumeClaim, whether created by this chart or supplied
externally.
*/}}
{{- define "alertint-agent.pvcName" -}}
{{- if .Values.persistence.existingClaim }}
{{- .Values.persistence.existingClaim }}
{{- else }}
{{- include "alertint-agent.fullname" . }}
{{- end }}
{{- end }}
