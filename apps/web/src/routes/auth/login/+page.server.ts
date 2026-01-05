import { fail, redirect } from '@sveltejs/kit';
import type { Actions } from './$types';

export const actions = {
	default: async ({ cookies, fetch, request, url }) => {
		const formData = await request.formData();
		const username = formData.get('username');
		const password = formData.get('password');
		const next = url.searchParams.get('next') || '/';
		
		const response = await fetch("/api/auth/local/login", {
            method: "POST",
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password })
        })
		if (!response.ok) {
			return fail(400, { username, incorrect: true });
		}
		const data = await response.json();
		for (const cookie of data.cookies) {
			cookies.set(cookie['name'], cookie['value'], {
                path: '/',
                httpOnly: true,
                secure: true,
                sameSite: 'lax',
            });
		}
		throw redirect(303, next);
	}
} satisfies Actions;
