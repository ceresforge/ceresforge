import { error } from '@sveltejs/kit';
import type { LayoutLoad } from './$types';

export type User = {
  id: number;
  username: string;
  created_at: string;
};

export const load: LayoutLoad = async ({ fetch, url }) => {
  //const apiEndpoint = '/api/users/self';
  //const res = await fetch(apiEndpoint, { headers: { accept: 'application/json' } });
  const result = await fetch('/api/users/self');
  const user: User = await result.json();
  return { user };
};
