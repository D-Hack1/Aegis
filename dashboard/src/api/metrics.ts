import { PipelineMetrics } from './types';

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
    // The browser's EventSource retries the connection on its own — surface
    // the disconnected state to the caller rather than fabricating metrics.
    onError(error);
  };

  // Return unsubscribe function
  return () => {
    eventSource.close();
  };
};
