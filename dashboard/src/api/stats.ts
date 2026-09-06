import { StatsResponse } from './types';

export const fetchStats = async (hours: number = 1): Promise<StatsResponse> => {
  try {
    const response = await fetch(`/stats?hours=${hours}`);
    if (!response.ok) throw new Error('Stats fetch failed');
    return await response.json();
  } catch (error) {
    console.warn("Failed to fetch stats, using mock data", error);
    
    // Generate some mock timeline buckets
    const now = new Date();
    const timeline = [];
    for (let i = 12; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 5 * 60000);
      timeline.push({
        bucket: d.toISOString(),
        count: Math.floor(Math.random() * 20) + 2
      });
    }

    return {
      total_alerts: 142,
      by_threat_class: {
        ddos: 34,
        c2_beaconing: 28,
        dns_anomaly: 19,
        malware_tls: 22,
        port_scan: 15,
        exfiltration: 12,
        unknown_anomaly: 12,
        benign: 0
      },
      by_severity: {
        critical: 41,
        high: 55,
        medium: 33,
        info: 13
      },
      timeline,
      top_src_ips: [
        { ip: "10.10.0.2", count: 47 },
        { ip: "10.10.0.3", count: 31 },
        { ip: "192.168.1.105", count: 18 },
        { ip: "192.168.1.50", count: 12 },
        { ip: "10.10.0.200", count: 8 }
      ]
    };
  }
};
