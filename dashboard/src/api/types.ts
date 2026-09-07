export type Severity = "critical" | "high" | "medium" | "info";
export type ThreatClass =
  | "ddos" | "c2_beaconing" | "dns_anomaly" | "malware_tls"
  | "port_scan" | "exfiltration" | "unknown_anomaly" | "benign";

export interface Alert {
  id: string;
  timestamp: string;
  flow_id: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  duration?: number;
  threat_class: ThreatClass;
  severity: Severity;
  confidence: number;
  anomaly_score: number;
  evidence: string[];
  kill_chain_id: string | null;
  ja3_hash?: string;
  ja4_hash?: string;
  is_quic?: boolean;
  quic_0rtt?: boolean;
}

export interface AlertsResponse {
  total: number;
  page: number;
  page_size: number;
  pages: number;
  results: Alert[];
}

export interface TimelineBucket {
  bucket: string;
  count: number;
}

export interface TopIp {
  ip: string;
  count: number;
}

export interface StatsResponse {
  total_alerts: number;
  by_threat_class: Record<ThreatClass, number>;
  by_severity: Record<Severity, number>;
  timeline: TimelineBucket[];
  top_src_ips: TopIp[];
}

export interface KillChainStage {
  alert_id: string;
  timestamp: string;
  threat_class: ThreatClass;
  severity: Severity;
  confidence: number;
  dst_ip: string;
  dst_port: number;
  evidence: string[];
}

export interface KillChain {
  chain_id: string;
  src_ip: string;
  first_seen: string;
  last_seen: string;
  stage_count: number;
  max_severity: Severity;
  stages: KillChainStage[];
}

export interface KillChainsResponse {
  total: number;
  chains: KillChain[];
}

export interface PipelineMetrics {
  ts: string;
  flows_per_sec: number;
  bytes_per_sec: number;
  kafka_queue_depth: number;
  pipeline_latency_ms: number;
  latency_ms_mean: number;
  window_flows: number;
}

export interface ServiceStatus {
  status: "ok" | "error";
  detail?: string;
}

export interface HealthResponse {
  status: "ok" | "degraded";
  uptime_seconds: number;
  model_loaded: boolean;
  isolation_forest_loaded: boolean;
  kafka: ServiceStatus & { bootstrap?: string };
  elasticsearch: ServiceStatus & { host?: string; index?: string };
}

export const SEVERITY_COLOURS: Record<Severity, string> = {
  critical: "bg-rose-500/10 text-rose-500 border border-rose-500/20",
  high: "bg-amber-500/10 text-amber-500 border border-amber-500/20",
  medium: "bg-yellow-500/10 text-yellow-500 border border-yellow-500/20",
  info: "bg-sky-500/10 text-sky-500 border border-sky-500/20",
};

export const SEVERITY_BORDER: Record<Severity, string> = {
  critical: "border-rose-500/30",
  high: "border-amber-500/30",
  medium: "border-yellow-500/30",
  info: "border-sky-500/30",
};

export const THREAT_CLASS_LABELS: Record<ThreatClass, string> = {
  ddos: "DDoS",
  c2_beaconing: "C2 Beaconing",
  dns_anomaly: "DNS Anomaly",
  malware_tls: "Malware (TLS)",
  port_scan: "Port Scan",
  exfiltration: "Exfiltration",
  unknown_anomaly: "Unknown Anomaly",
  benign: "Benign",
};
