<script lang="ts">
	import favicon from '$lib/assets/favicon.svg';

	let { children } = $props();
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
</svelte:head>

<header>
	<nav>
		<a href="/">
			<img src="{favicon}" alt="CeresForge">
		</a>
		<a href="/admin">Admin</a>
	</nav>
</header>
<main>
    <article>
		{@render children?.()}
	</article>
</main>
