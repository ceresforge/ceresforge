import { error } from '@sveltejs/kit';
import type { PageLoad } from './$types';

export type User = {
  id: number;
  username: string;
  created_at: string;
};

export const load: PageLoad = async ({ fetch, url }) => {
  const apiEndpoint = `${url.origin}/api/users`;
  const res = await fetch(apiEndpoint, { headers: { accept: 'application/json' } });
  if (!res.ok) {
    throw error(res.status, await res.text());
  }
  const users: User[] = await res.json();
  return { users };
};
