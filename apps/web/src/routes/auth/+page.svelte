<script lang="ts">
    import type { PageProps } from './$types';

    let { data }: PageProps = $props();
    
    let title = 'Auth';
    let description = 'Authenticate to CeresForge.';
</script>

<svelte:head>
    <title>{title}</title>
    <meta name="description" content={description}> 
</svelte:head>

<h1>{title}</h1>
<p>{description}</p>
