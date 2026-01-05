import type { HandleFetch } from '@sveltejs/kit';

export const handleFetch: HandleFetch = async ({ event, request, fetch }) => {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api') && url.origin === event.url.origin) {
        request = new Request(
            `http://127.0.0.1:8080${url.pathname}${url.search}`,
            request
        );
    }
    return fetch(request);
};
