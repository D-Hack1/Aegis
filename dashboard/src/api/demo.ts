export const launchAttack = async (type: string): Promise<{status: string, attack: string}> => {
  const response = await fetch(`/demo/attack?type=${type}`, {
    method: 'POST',
  });
  if (!response.ok) {
    throw new Error('Failed to launch attack');
  }
  return response.json();
};

export const resetDashboard = async (): Promise<{status: string, deleted: number}> => {
  const response = await fetch('/demo/reset');
  if (!response.ok) {
    throw new Error('Failed to reset dashboard');
  }
  return response.json();
};
