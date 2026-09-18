import { Alert, AlertsResponse } from './types';

export const fetchAlerts = async (params?: Record<string, any>): Promise<AlertsResponse> => {
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
};

export const fetchAlertById = async (id: string): Promise<Alert> => {
  const response = await fetch(`/alerts/${id}`);
  if (!response.ok) throw new Error('Alert not found');
  return await response.json();
};
