import type { HandleFetch } from '@sveltejs/kit';

export const handleFetch: HandleFetch = async ({ request, fetch }) => {
    if (request.url.startsWith('http://localhost:5173')) {
		request = new Request(
			request.url.replace('http://localhost:5173', 'http://localhost:8080'),
			request
		);
	}
	return fetch(request);
};
