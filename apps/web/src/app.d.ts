// See https://svelte.dev/docs/kit/types#app.d.ts
// for information about these interfaces
declare global {

	interface User {
        id: number;
        username: string;
        created_at: string;
    }

	namespace App {
		// interface Error {}
		// interface Locals {}
		interface PageData {
			user: User | null;
		}
		// interface PageState {}
		// interface Platform {}
	}
}

export {};
