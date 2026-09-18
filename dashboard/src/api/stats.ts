import { StatsResponse } from './types';

export const fetchStats = async (hours: number = 1): Promise<StatsResponse> => {
  const response = await fetch(`/stats?hours=${hours}`);
  if (!response.ok) throw new Error('Stats fetch failed');
  return await response.json();
};
