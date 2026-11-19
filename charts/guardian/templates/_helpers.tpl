{{/* Names and labels. */}}
{{- define "guardian.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "guardian.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "guardian.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "guardian.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "guardian.backendSelector" -}}
app.kubernetes.io/name: {{ include "guardian.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: backend
{{- end -}}

{{- define "guardian.postgresSelector" -}}
app.kubernetes.io/name: {{ include "guardian.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: postgres
{{- end -}}

{{- define "guardian.postgresName" -}}
{{- printf "%s-postgres" (include "guardian.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* The host of issuerURL, for routing. */}}
{{- define "guardian.host" -}}
{{- (urlParse (required "issuerURL is required" .Values.issuerURL)).hostname -}}
{{- end -}}

{{/* The Secret holding the database password. */}}
{{- define "guardian.dbPasswordSecret" -}}
{{- default .Values.secrets.existingSecret .Values.database.passwordSecret -}}
{{- end -}}

{{- define "guardian.image" -}}
{{- printf "%s:%s" (required "image.repository is required" .Values.image.repository) (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
