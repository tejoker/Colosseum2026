{{- define "sauronid.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{- define "sauronid.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "sauronid.labels" -}}
app.kubernetes.io/name: {{ include "sauronid.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "sauronid.secretName" -}}
{{- required "existingSecret must name a pre-created Secret holding the SauronID secrets (see values.yaml)" .Values.existingSecret -}}
{{- end -}}
