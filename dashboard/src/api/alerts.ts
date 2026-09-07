import { Alert, AlertsResponse } from './types';

export const fetchAlerts = async (params?: Record<string, any>): Promise<AlertsResponse> => {
  try {
    const searchParams = new URLSearchParams();
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value) searchParams.append(key, String(value));
      });
    }
    
    const query = searchParams.toString();
    const url = `/alerts${query ? `?${query}` : ''}`;
    
    const response = await fetch(url);
    if (!response.ok) throw new Error('Network response was not ok');
    
    return await response.json();
  } catch (error) {
    console.warn("Failed to fetch real alerts, using mock data", error);
    // Return mock data for UI testing if backend is down
    return {
      total: 1,
      page: 1,
      page_size: 20,
      pages: 1,
      results: [
        {
          id: "mock-1234",
          timestamp: new Date().toISOString(),
          flow_id: "CmFTSk3bQhXgPzL19",
          src_ip: "10.10.0.2",
          dst_ip: "10.10.0.5",
          src_port: 54321,
          dst_port: 443,
          protocol: "tcp",
          threat_class: "c2_beaconing",
          severity: "critical",
          confidence: 0.94,
          anomaly_score: 0.72,
          evidence: [
            "Repeated communication at fixed intervals",
            "Unusual TLS client fingerprint (JA3)",
            "Low destination IP entropy"
          ],
          kill_chain_id: "kc-uuid-1234"
        }
      ]
    };
  }
};

export const fetchAlertById = async (id: string): Promise<Alert> => {
  try {
    const response = await fetch(`/alerts/${id}`);
    if (!response.ok) throw new Error('Alert not found');
    return await response.json();
  } catch (error) {
    console.warn(`Failed to fetch alert ${id}, using mock data`);
    return {
      id,
      timestamp: new Date().toISOString(),
      flow_id: "CmFTSk3bQhXgPzL19",
      src_ip: "10.10.0.2",
      dst_ip: "10.10.0.5",
      src_port: 54321,
      dst_port: 443,
      protocol: "tcp",
      duration: 12.4,
      threat_class: "c2_beaconing",
      severity: "critical",
      confidence: 0.94,
      anomaly_score: 0.72,
      evidence: [
        "Repeated communication at fixed intervals",
        "Unusual TLS client fingerprint (JA3)",
        "Low destination IP entropy — narrow target set"
      ],
      kill_chain_id: "kc-uuid-1234",
      ja3_hash: "a0e9f5d64349fb13191bc781f81f42e1",
      ja4_hash: "t13d1516h2_8daaf6152771_b0da82dd1658",
      is_quic: false,
      quic_0rtt: false
    };
  }
};
