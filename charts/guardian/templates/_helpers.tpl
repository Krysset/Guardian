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

{{- define "guardian.frontendName" -}}
{{- printf "%s-frontend" (include "guardian.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "guardian.frontendSelector" -}}
app.kubernetes.io/name: {{ include "guardian.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: frontend
{{- end -}}

{{- define "guardian.frontendImage" -}}
{{- printf "%s:%s" (required "frontend.image.repository is required when frontend.enabled is true" .Values.frontend.image.repository) (default .Chart.AppVersion .Values.frontend.image.tag) -}}
{{- end -}}

{{/* Pods of this release that run the guardian binary and so may reach the database: the backend, the
     migration Job and the backup CronJob. */}}
{{- define "guardian.databaseClient" -}}
app.kubernetes.io/instance: {{ .Release.Name }}
guardian.dev/database-client: "true"
{{- end -}}

{{/* The environment of a guardian command outside the Deployment (the migration Job, which runs as a hook
     and so cannot rely on this release's ConfigMap being current): the database, the issuer and the
     keyring file. */}}
{{- define "guardian.commandEnv" -}}
- name: ISSUER_URL
  value: {{ trimSuffix "/" .Values.issuerURL | quote }}
- name: LOG_FORMAT
  value: {{ .Values.config.logFormat | quote }}
- name: KEY_ENCRYPTION_KEYS_FILE
  value: /etc/guardian/keyring/keys
{{- if eq .Values.database.mode "bundled" }}
- name: DB_HOST
  value: {{ include "guardian.postgresName" . | quote }}
- name: DB_PORT
  value: "5432"
- name: DB_USER
  value: {{ .Values.database.bundled.user | quote }}
- name: DB_NAME
  value: {{ .Values.database.bundled.name | quote }}
- name: DB_SSLMODE
  value: disable
{{- else }}
- name: DB_HOST
  value: {{ required "database.external.host is required when database.mode is external" .Values.database.external.host | quote }}
- name: DB_PORT
  value: {{ .Values.database.external.port | quote }}
- name: DB_USER
  value: {{ .Values.database.external.user | quote }}
- name: DB_NAME
  value: {{ .Values.database.external.name | quote }}
- name: DB_SSLMODE
  value: {{ .Values.database.external.sslMode | quote }}
{{- end }}
- name: DB_MAX_CONNS
  value: "2"
- name: DB_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "guardian.dbPasswordSecret" . }}
      key: {{ .Values.database.passwordKey }}
{{- end -}}

{{/* The keyring volume, shared by every pod that runs the guardian binary. */}}
{{- define "guardian.keyringVolume" -}}
- name: keyring
  secret:
    secretName: {{ .Values.secrets.existingSecret }}
    defaultMode: 0440   # readable by the pod's fsGroup (podSecurityContext)
    items:
      - key: {{ .Values.secrets.keys.keyEncryptionKeys }}
        path: keys
{{- end -}}
