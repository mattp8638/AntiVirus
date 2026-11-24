# Dedup groups (cross-repository deduplication)

Within one repository, every machine's backups already share chunks: data two machines have in common is
stored once. Repositories do not share with each other, because each derives its chunk IDs and chunk encryption
from its own master key: the same data has different chunk IDs in two repositories and nothing can tell that it
is the same.

A dedup group is a set of repositories in one storage location that share one **group key** for chunks, and so
one chunk store. Each member keeps its own master key, passphrase, recovery key, signers and manifests.

## Layout

```text
<group>/group.json                      plaintext: group id, chunk size
<group>/chunks/<aa>/<64 hex>            chunks of every member (group key)
<group>/locks/                          one set of repository locks for the group
<group>/refs/<repo id>/<image id>       each image's chunk list (group key)
<group>/repos/<repo id>/config.json     a member (format version 2, "group": id)
                       keys/ signers/ manifests/
                       group-key.json   the group key, sealed with the member's master key
```

A member's path is `<group>/repos/<repo id>`; opening it routes `chunks/`, `locks/` and `refs/` to the group
folder and everything else to the member's folder (`core_format::group::GroupBackend`). Members use version 2 of
the repository format, so an older Fenrir-Backup refuses to open one instead of misreading its chunks.

## Keys

* Chunk ID key and chunk encryption key: derived from the group key (as a plain repository derives them from its
  master key). The same data in two members is the same chunk.
* Manifest encryption and signer keys: from the member's master key. A member cannot read another member's
  manifests (which machines, which disks, when).
* The group key is stored in each member, sealed with that member's master key
  (`group-key.json`, XChaCha20-Poly1305, bound to the group and repository IDs).

**What a group gives up.** Anyone who can open one member (its passphrase or recovery key) holds the group key
and can decrypt every chunk in the group, including other members' data, though not their manifests that say
what the data is. A group is for repositories of one owner (one customer), never across customers. The server
only lets a repository join the group of a repository the same administrator manages, created by a machine that
can already open that repository.

## Creating

* New group: the first member's folder is `<chosen folder>/repos/<its id>`; the agent (or `repo init
  --dedup-group new`) writes `group.json`, generates the group key and creates the member.
* Joining: the new member goes in the same group folder. The machine creating it opens an existing member with
  the access it already has (the server sends that access with the job as `group_source`), takes the group key,
  and creates the new member with it (`repo init --dedup-group <member path>` with that member's passphrase).
  All members use the group's chunk size.

An existing ordinary repository cannot be converted: its chunks are keyed by its own master key.

## Deleting safely

Retention deletes a member's manifests; pruning deletes chunks nobody uses. With shared chunks "nobody" includes
the other members, whose manifests a member cannot read. So each member, when it stores a manifest, first writes
the image's chunk list to `refs/<repo id>/<image id>`, encrypted with the group key; deleting an image deletes
the manifest, then the list. Prune (exclusive lock, which is the group's lock):

1. reads this member's manifests and every chunk list in the group; if any list cannot be decrypted, it deletes
   nothing;
2. removes this member's lists whose manifest is gone (a crash between the two writes);
3. deletes chunks in none of them.

A list written before its manifest, or left after its manifest was deleted, only keeps chunks longer. Backups in
any member take the group's shared lock, so a prune in another member cannot delete a chunk a running backup has
just found and reused.

With object locks (S3 Object Lock, Azure immutability) each member's maintenance extends the locks of the chunks
its own images use, its chunk lists and its own files.

## Tests

* `engine/tests/engine.rs` `dedup_group_members_share_chunks_and_prune_safely`: the second member stores nothing
  new for the same disk; members cannot read each other's manifests or open with each other's passphrase; pruning
  one member keeps chunks the other uses and restores still work; a crash-left list is cleaned up; a damaged list
  stops the prune; when no member uses a chunk any more it is deleted.
* `cli/tests/cli.rs` `dedup_group_from_the_command_line`.
* `server/tests/api.rs` `dedup_group_repositories_share_storage_and_key`: paths, the group key's source sent to
  the creating machine, refusal without access, and joining only in the group's location.
