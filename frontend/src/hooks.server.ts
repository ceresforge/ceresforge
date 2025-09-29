import type { HandleFetch } from '@sveltejs/kit';
import { NODE_ENV } from '$env/static/private';

export const handleFetch: HandleFetch = async ({ request, fetch }) => {
    let frontendUrl = NODE_ENV === 'production'
                      ? 'http://localhost:3000'
                      : 'http://localhost:5173';
    if (request.url.startsWith(frontendUrl)) {
        request = new Request(
            request.url.replace(frontendUrl, 'http://127.0.0.1:8080'),
            request
        );
    }
    return fetch(request);
};
