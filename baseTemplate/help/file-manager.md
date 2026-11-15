# File Manager

The File Manager lets you work with a website's files in the browser, as the website's own Linux user. It starts in `/home/<domain>/`; the web root is `public_html`.

## Opening it

Open **Websites > List Websites**, choose the site and click **File Manager**.

## Common tasks

- **Upload**: drag files into the upload window or pick them, then **Upload all**. Large sites are easier to move with [FTP](/base/help/ftp) or [SFTP](/base/help/ssh-manager).
- **New File / New Folder**: created in the current directory. An existing file is not overwritten.
- **Edit**: opens text files in the editor; click **Save Changes**.
- **Copy, Move, Rename, Delete**: select items with the checkboxes first. Deleted items go to the trash unless you tick **Skip Trash Folder**.
- **Compress / Extract**: create `zip` or `tar.gz` archives; enter `.` to extract into the current directory.
- **Fix Permissions**: resets ownership and permissions of the site files to safe defaults. Use it after uploads that break with "403 Forbidden".

## Server-wide files

The site File Manager cannot leave the website's home directory. Administrators can use the [Root File Manager](/addons/root-file-manager/) add-on for the whole server, with protected paths, trash and an audit log.

## Common problems

- **Upload stops or fails**: check the upload limits shown in the upload window and the free disk space of the package.
- **Permission denied on edit**: the file is owned by another user (for example root). Run **Fix Permissions**.
