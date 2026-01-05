import { error } from '@sveltejs/kit';
import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = async ({ fetch }) => {
  const response = await fetch('/api/users/self');
  if (response.status === 401) {
    return { user: null };
  }
  const user = await response.json();
  return { user };
};
