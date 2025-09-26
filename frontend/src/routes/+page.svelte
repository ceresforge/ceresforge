<script lang="ts">
    let title = 'CeresForge';
    let description = 'A web platform for learning, creating, and testing software.';
</script>

<svelte:head>
    <title>{title}</title>
    <meta name="description" content={description} /> 
</svelte:head>

<h1>{title}</h1>
<p>{description}</p>
