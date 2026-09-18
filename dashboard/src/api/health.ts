import { HealthResponse } from './types';

export const fetchHealth = async (): Promise<HealthResponse> => {
  const response = await fetch('/health');
  if (!response.ok) throw new Error('Health check failed');
  return await response.json();
};
