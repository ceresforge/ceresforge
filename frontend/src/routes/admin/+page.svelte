<script lang="ts">
    import type { PageProps } from './$types';

	let { data }: PageProps = $props();
    
    let title = 'Admin';
    let description = 'Displays administrator information.';
</script>

<svelte:head>
    <title>{title}</title>
    <meta name="description" content={description} /> 
</svelte:head>

<h1>{title}</h1>
<p>{description}</p>

{#if data.users.length === 0}
  <p>No users found.</p>
{:else}
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>Username</th>
        <th>Created</th>
      </tr>
    </thead>
    <tbody>
      {#each data.users as user}
        <tr>
          <td>{user.id}</td>
          <td><code>{user.username}</code></td>
          <td>{new Date(user.created_at).toLocaleDateString()}</td>
        </tr>
      {/each}
    </tbody>
  </table>
{/if}
