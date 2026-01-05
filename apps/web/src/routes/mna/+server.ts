import { error } from '@sveltejs/kit';

export const fallback = ({ request }) => {
    throw error(405, 'Method Not Allowed');
};
