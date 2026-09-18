import { KillChainsResponse } from './types';

export const fetchKillChains = async (hours: number = 1): Promise<KillChainsResponse> => {
  const response = await fetch(`/kill-chains?hours=${hours}`);
  if (!response.ok) throw new Error('Kill chains fetch failed');
  return await response.json();
};
