# CloudLinux and CageFS

CloudLinux OS limits CPU, memory and processes per account, and CageFS gives each user an isolated file system so users cannot see each other. The panel's CloudLinux pages work only on servers running CloudLinux OS.

## Converting a server

CloudLinux needs a licence from CloudLinux. On a supported AlmaLinux or Rocky Linux server, CloudLinux provides the `cldeploy` script that converts the server in place:

```
wget https://repo.cloudlinux.com/cloudlinux/sources/cln/cldeploy
sh cldeploy -k <activation_key>
```

Reboot afterwards. Take a full backup or snapshot before converting.

## In the panel

- **Server > CloudLinux Usage** and **CageFS** appear once CloudLinux is installed and activated. Use **Activate Now** if the page reports it is installed but not activated.
- On a website's **SSH/SFTP Access** page you can turn CageFS on or off for that user.

## Without CloudLinux

[Resource Limits](/addons/limits/) in Universal Add-ons sets per-site PHP memory, process and connection limits through OpenLiteSpeed on any supported OS.
