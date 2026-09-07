import { PipelineMetrics } from './types';

let mockInterval: any = null;

export const subscribePipelineMetrics = (
  onMessage: (data: PipelineMetrics) => void,
  onError: (error: Event) => void
): (() => void) => {
  const eventSource = new EventSource('/metrics');

  eventSource.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data) as PipelineMetrics;
      onMessage(data);
    } catch (e) {
      console.error("Error parsing metrics SSE data:", e);
    }
  };

  eventSource.onerror = (error) => {
    console.warn("SSE connection error, falling back to mock generation", error);
    onError(error);
    
    // If SSE fails, fallback to generating mock metrics locally every 2 seconds
    if (!mockInterval) {
      mockInterval = setInterval(() => {
        const mockData: PipelineMetrics = {
          ts: new Date().toISOString(),
          flows_per_sec: 80 + Math.random() * 20,
          bytes_per_sec: 140000 + Math.random() * 10000,
          kafka_queue_depth: Math.floor(Math.random() * 15),
          pipeline_latency_ms: 40 + Math.random() * 15, // Change this to >100 or >500 to test colors
          latency_ms_mean: 45 + Math.random() * 5,
          window_flows: 160 + Math.floor(Math.random() * 40)
        };
        onMessage(mockData);
      }, 2000);
    }
  };

  // Return unsubscribe function
  return () => {
    eventSource.close();
    if (mockInterval) {
      clearInterval(mockInterval);
      mockInterval = null;
    }
  };
};
