<script lang="ts">
    import { goto, invalidateAll } from '$app/navigation';
    import type { PageProps } from './$types';

    let { data }: PageProps = $props();

    let title = 'CeresForge';
    let description = 'A web platform for learning, creating, and testing software.';

    let isLoggingOut = $state(false);

    async function handleLogout() {
        isLoggingOut = true;
        
        try {
            const response = await fetch('/api/auth/logout', {
                method: 'POST'
            });

            if (response.ok) {
                await invalidateAll();
                await goto('/auth/login');
            } else {
                console.error('Logout failed on the backend');
            }
        } catch (err) {
            console.error('Network error during logout', err);
        } finally {
            isLoggingOut = false;
        }
    }
</script>

<svelte:head>
    <title>{title}</title>
    <meta name="description" content={description}> 
</svelte:head>

<h1>{title}</h1>
<p>{description}</p>

{#if data.user}
    <p>Welcome <strong>{data.user.username}</strong></p>
    
    <button type="button" onclick={handleLogout} disabled={isLoggingOut}>
        {isLoggingOut ? 'Logging out...' : 'Logout'}
    </button>
{:else}
    <p><a href="/auth/login">Please log in</a></p>
{/if}
