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
Fails the render with a clear message if the Secret modes are misconfigured.
Exactly one of these three shapes is valid:
  - secret.enabled: false, with neither create nor existingSecret set (the
    deliberate no-Secret opt-out).
  - secret.enabled: true (default) with exactly one of create/existingSecret.
Anything else — both create and existingSecret set (regardless of enabled),
or enabled: false alongside create/existingSecret (the Deployment would
ignore whichever Secret those select, since envFrom is only rendered when
enabled is true), or enabled: true with neither set — fails loudly instead
of silently referencing or creating a Secret nothing actually uses.
*/}}
{{- define "alertint-agent.validateSecret" -}}
{{- if and .Values.secret.create .Values.secret.existingSecret }}
{{- fail "secret.create and secret.existingSecret are mutually exclusive — set only one." }}
{{- end }}
{{- if not .Values.secret.enabled }}
{{- if or .Values.secret.create .Values.secret.existingSecret }}
{{- fail "secret.enabled is false, but secret.create or secret.existingSecret is also set. With enabled=false the Deployment never references the built-in Secret, so whichever one you configured here would be created/referenced but silently ignored. Either remove secret.create/secret.existingSecret, or set secret.enabled=true (the default) to actually use them." }}
{{- end }}
{{- else if and (not .Values.secret.create) (not .Values.secret.existingSecret) }}
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
Effective MCP enablement. AlertINT cannot start the MCP server without a
non-empty token_env value regardless of config.mcp.enabled's own setting
(per app behavior confirmed in review) — so, unlike a simple presence-based
mirror, an explicit `enabled: true` is NOT on its own treated as "enabled"
here: it still has to be backed by actual, checkable token evidence. An
explicit `enabled: false` is the one case that always wins outright, since
that's a deliberate opt-out independent of any token.
  "enabled"  - config.mcp.enabled is not explicitly false, AND a non-empty
               value for token_env is positively confirmed: either
               secret.create carries it in secret.data, or extraEnv has a
               literal (non-valueFrom) value for it.
  "disabled" - config.mcp.enabled is explicitly false, OR no source the
               chart can see supplies token_env at all.
  "unknown"  - configOverride/existingConfigMap is used (config.mcp itself
               is unused so nothing here can be trusted); OR
               secret.existingSecret is used; OR extraEnvFrom is set; OR
               extraEnv references token_env via valueFrom — in each case
               something might supply the token, but the chart can't see
               its actual value to confirm.
*/}}
{{- define "alertint-agent.mcpState" -}}
{{- if or .Values.configOverride .Values.existingConfigMap -}}
unknown
{{- else -}}
{{- $mcp := .Values.config.mcp | default dict -}}
{{- $tokenEnv := $mcp.token_env -}}
{{- if and (hasKey $mcp "enabled") (not $mcp.enabled) -}}
disabled
{{- else if and .Values.secret.create $tokenEnv (index .Values.secret.data $tokenEnv) -}}
enabled
{{- else if .Values.secret.existingSecret -}}
unknown
{{- else if .Values.extraEnvFrom -}}
unknown
{{- else -}}
{{- $found := "" -}}
{{- range .Values.extraEnv -}}
{{- if eq .name $tokenEnv -}}
{{- if .value -}}
{{- $found = "present" -}}
{{- else -}}
{{- $found = "unknown" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if eq $found "present" -}}
enabled
{{- else if eq $found "unknown" -}}
unknown
{{- else -}}
disabled
{{- end -}}
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
