# Git for websites

**Manage Git** tracks a website folder with git, connects it to a remote repository and can deploy on push through a webhook.

## Getting started

1. Open the website's page and click **Manage Git**.
2. **Select Folder to Track** (usually `public_html`).
3. If the folder is not a repository yet, click **Init Repo**, or click **Attach Existing Repo** and enter the **Git Host**, **Username** and **Repo Name**. Add the shown **Deployment Key** to the repository (read access, or write access to push).

## Daily use

- **Commit Changes** with a message, **Pull** and **Push**, **Create New Branch** and switch branches.
- **Edit .gitignore** to exclude caches and uploads.
- **View Commits** shows history; **View/Setup Remote** shows or changes the remote.
- **Configure**: set **Auto Commit** and **Auto Push** (never, daily, weekly), email logs, and **Commands** to run when the **Webhook URL** is called. Add that URL as a push webhook in your Git host to deploy automatically.

## Common problems

- **Permission denied (publickey)**: the deployment key is not added to the repository, or lacks write access for push.
- **Remove Git Tracking** deletes the history (`.git`) but keeps your files. It cannot be undone.
