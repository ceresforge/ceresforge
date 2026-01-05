import { error } from '@sveltejs/kit';
import type { PageLoad } from './$types';

export type User = {
  id: number;
  username: string;
  email: string;
  created_at: string;
};

export const load: PageLoad = async ({ fetch, url }) => {
  const endpoint = `${url.origin}/api/users`;
  const res = await fetch(endpoint, { headers: { accept: 'application/json' } });
  if (!res.ok) {
    throw error(res.status, res.statusText);
  }
  const users: User[] = await res.json();
  return { users };
};
