<script lang="ts">
    import type { PageProps } from './$types';

    let { data, form }: PageProps = $props();
    
    let title = 'Login';
    let description = 'Please enter your username and password.';
</script>

<svelte:head>
    <title>{title}</title>
    <meta name="description" content={description}> 
</svelte:head>

<h1>{title}</h1>
<p>{description}</p>

{#if data.user}
    <p>You're already logged in as <strong>{data.user.username}</strong></p>
{/if}

<form method="POST">
    {#if form?.incorrect}<p class="error">Invalid credentials!</p>{/if}
	<label>
		Username
		<input
            name="username"
            type="text"
            required
            minlength="3"
            maxlength="31"
            autocomplete="username"
        >
	</label>
	<label>
		Password
		<input
            name="password"
            type="password"
            required
            autocomplete="current-password"
        >
	</label>
	<button>Log in</button>
</form>
