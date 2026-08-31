{{- define "ntwire.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "ntwire.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := include "ntwire.name" . }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "ntwire.labels" -}}
helm.sh/chart: {{ include "ntwire.name" . }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "ntwire.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: {{ .Values.component }}
{{- end }}

{{- define "ntwire.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ntwire.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: {{ .Values.component }}
{{- end }}

{{- define "ntwire.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "ntwire.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "ntwire.configFile" -}}
{{- if eq .Values.component "server" -}}ntwire.yaml{{- else if eq .Values.component "relay" -}}ntwire-relay.yaml{{- else -}}config.yaml{{- end -}}
{{- end }}

{{- define "ntwire.image" -}}
{{- $repository := .Values.image.repository -}}
{{- if not $repository -}}
{{- $repository = printf "nmaguiar/ntwire-%s" .Values.component -}}
{{- end -}}
{{- printf "%s:%s" $repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end }}
