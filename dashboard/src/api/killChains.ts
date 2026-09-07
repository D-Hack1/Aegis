import { KillChainsResponse } from './types';

export const fetchKillChains = async (hours: number = 1): Promise<KillChainsResponse> => {
  try {
    const response = await fetch(`/kill-chains?hours=${hours}`);
    if (!response.ok) throw new Error('Kill chains fetch failed');
    return await response.json();
  } catch (error) {
    console.warn("Failed to fetch kill chains, using mock data", error);
    
    const now = new Date();
    const earlier1 = new Date(now.getTime() - 45 * 60000).toISOString();
    const earlier2 = new Date(now.getTime() - 15 * 60000).toISOString();
    const earlier3 = new Date(now.getTime() - 2 * 60000).toISOString();

    return {
      total: 1,
      chains: [
        {
          chain_id: "kc-uuid-1234",
          src_ip: "10.10.0.2",
          first_seen: earlier1,
          last_seen: earlier3,
          stage_count: 3,
          max_severity: "critical",
          stages: [
            {
              alert_id: "xyz789",
              timestamp: earlier1,
              threat_class: "port_scan",
              severity: "medium",
              confidence: 0.87,
              dst_ip: "10.10.0.5",
              dst_port: 0,
              evidence: ["Single source contacted many ports or hosts"]
            },
            {
              alert_id: "abc123",
              timestamp: earlier2,
              threat_class: "malware_tls",
              severity: "high",
              confidence: 0.81,
              dst_ip: "10.10.0.5",
              dst_port: 443,
              evidence: ["Unusual TLS client fingerprint (JA4)", "QUIC 0-RTT resumption detected"]
            },
            {
              alert_id: "def456",
              timestamp: earlier3,
              threat_class: "c2_beaconing",
              severity: "critical",
              confidence: 0.94,
              dst_ip: "10.10.0.5",
              dst_port: 443,
              evidence: ["Repeated communication at fixed intervals"]
            }
          ]
        }
      ]
    };
  }
};
