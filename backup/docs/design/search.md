# Design note: searching across backups

Status: implemented (crate `catalog`, agent `search.rs`, Fenrir Cloud
`POST /backup/search`).

"Where is `budget.xlsx`, and which backups have it?" Browsing one backup at
a time does not answer that.

## 1. Catalogues

A catalogue lists every file and folder of an image's browsable volumes
(NTFS and ext2/3/4 inside disk images; everything in a folder backup): path,
size and modification time, no contents. Images never change, so a
catalogue stays valid for the image's life and can always be rebuilt.

* After each backup, Fenrir Cloud queues an `IndexImage` job on the machine
  that took it; the agent walks the image through `filebrowse` (or the
  folder backup's index) and keeps the catalogue in its state directory,
  `catalogue/<repository id>/<image id>.zst` (zstd-compressed JSON).
* A search that meets an image without a catalogue (another machine, an old
  backup) builds it while its time budget lasts (2 minutes by default) and
  reports the rest as not indexed yet; the next search continues.
* Up to 300 catalogues are kept per repository, the least recently used
  dropped first.

## 2. Privacy

The repository format is unchanged and Fenrir Cloud holds no file lists:
catalogues stay on the machines that built them. File names reach the
server only as the matches of a search, which are dropped from the job
record after a day, like folder listings. Searching needs the repository to
be unlocked in the browser session and the scripts permission, as browsing
does, and every search is audited (`backup.search`, with the query).

## 3. Queries

* Words: all must appear in the file or folder name, in any order, ignoring
  case (`budget 2026`).
* `*` and `?` wildcards match the whole name (`*.xlsx`, `budget-202?.xlsx`).
* With a `/`, the path is matched instead (`anna/pictures`); in a path
  pattern `*` does not cross folders (`Documents/*.xlsx`).

One job per repository runs on a machine with access (the one the backups
came from first), over the machine's backups newest first (at most 500), and
returns at most 500 matches.

## 4. In the console

Images & restore › a machine › **Find a file in these backups**: results
grouped by item with the number of backups holding it; **Open newest** or
any version opens Browse files at that folder with the item ticked, ready to
restore or download.

## 5. Tests

* `catalog`: words, wildcards and path patterns, folders found, the root's
  own entry skipped, limits, save and load.
* `scan/tests/image.rs`: a real NTFS and ext4 backup is catalogued and
  searched (sizes, times, volumes).
* `cloud/tests/test_device_backup.py`: indexing queued after each backup,
  search needs an unlock, images newest first, matches purged after a day.
