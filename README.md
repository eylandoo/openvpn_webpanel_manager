# OVPN Manager: A Powerful Web Panel for OpenVPN

[![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.x-black?logo=flask)](https://flask.palletsprojects.com/)
[![Tailwind CSS](https://img.shields.io/badge/UI-Tailwind_CSS-38B2AC?logo=tailwind-css)](https://tailwindcss.com/)
[![License: All Rights Reserved](https://img.shields.io/badge/License-All_Rights_Reserved-blue)](LICENSE)


OVPN Manager is a comprehensive, self-hosted web panel built with Flask to streamline the management of OpenVPN servers. It provides a modern, user-friendly, and feature-rich interface for managing users, resellers (sub-admins), and even multi-node deployments, turning complex server administration into a simple point-and-click experience.

This panel is designed for administrators who need granular control over user access, traffic, and server resources, all from a centralized and intuitive dashboard.

### 📸 Dashboard Preview

![OVPN Manager Dashboard](https://uploadkon.ir/uploads/803c11_25eylanpanel.png)
---

## ✨ Key Features

### User Management
* **Create Users**: Add single or bulk users with randomly generated usernames.
* **Detailed Limits**: Set specific limits for each user:
    * **Data Limit**: Assign quotas in GB or MB.
    * **Connection Limit**: Define the maximum number of simultaneous connections.
    * **Expiry Date**: Set fixed expiration dates or flexible durations that start after the user's first connection.
* **Real-time Control**: Activate or deactivate users instantly.
* **Traffic Monitoring**: View live and cumulative data usage (Upload/Download) for each user.
* **Easy Access**: Download user `.ovpn` configuration files directly from the panel.
* **Subscription Page**: Each user gets a unique, token-based subscription page showing their stats, QR code, and download links.

### Sub-Admin (Reseller) System
* **Create Sub-Admins**: Main admin can create sub-admin (reseller) accounts.
* **Assign Quotas**: Set limits for each sub-admin, including maximum number of users they can create and a total data quota they can assign.
* **Independent Management**: Sub-admins can log in to a simplified panel to manage their own users within the limits you've set.

### Multi-Node Support
* **Centralized Control**: Manage and sync users across multiple OpenVPN servers (nodes) from a single main panel.
* **Node Health Monitoring**: View the live status of all connected nodes.
* **Selective Access**: Assign specific nodes to users, giving you control over which servers they can connect to.

### Server & Panel Administration
* **Live System Stats**: Monitor real-time server resource usage, including CPU, RAM, and Disk space.
* **Service Control**: Start, stop, and restart OpenVPN and panel services directly from the dashboard.
* **Backup & Restore**: Create full backups of your users and configurations. Supports manual download and automated backups to Telegram.
* **SSL Management**: Secure your panel with SSL certificates. Supports both manual uploads and automatic generation via Let's Encrypt.
* **Advanced Configuration**: Directly edit `server.conf` for the main server and each node from within the UI for expert-level adjustments.
* **Customization**: Change the panel port, set a custom admin URL path, and switch between dark and light themes.

### API
* **Full Automation**: A secure, key-based RESTful API allows for programmatic management of users, including creation, editing, deletion, and status retrieval.

---

## 🛠️ Architecture & Tech Stack

The panel is a robust Flask application that acts as the brain of the operation. It interacts with the system to manage users and services.

* **Backend**: **Flask**, **Gevent** (for WSGI), **SQLAlchemy** (for database ORM)
* **Database**: **SQLite**
* **Core Management**: Interacts directly with an `openvpn.sh` script for user provisioning and `systemctl` for service management.
* **Frontend**: **Tailwind CSS**, **Font Awesome**, Vanilla JavaScript
* **Scheduling**: **APScheduler** for background tasks like traffic updates and license checks.

---

## 🚀 Installation Guide

The installation process is fully automated using a management script.

### *Prerequisites*
* A server running **Ubuntu 22.04 (x86_64)**. The installer will not work on other versions.
* Root (`sudo`) access to the server.

### *Step 1: Run the Installer*
Connect to your server via SSH and run the single command below. This will download the main management script and start the installation menu.

```bash
wget -q -O /root/vpn_manager.sh [https://raw.githubusercontent.com/eylandoo/openvpn_webpanel_manager/main/vpn_manager.sh](https://raw.githubusercontent.com/eylandoo/openvpn_webpanel_manager/main/vpn_manager.sh) && chmod +x /root/vpn_manager.sh && /root/vpn_manager.sh
```

### *Step 2: Install OpenVPN Core*
After running the command, an interactive menu will appear.

1.  Select the **`Install OpenVPN Core`** option.
2.  You will be prompted to choose a protocol (**UDP** or **TCP**) and a **Port** for your OpenVPN server.
3.  The script will handle the installation automatically.

### *Step 3: Install the Web Panel*
Once the OpenVPN core is installed, you will return to the main menu.

1.  Select the **`Install OpenVPN Web Panel`** option.
2.  The script will ask for the following details:
    * **Admin Username**: The username for logging into the web panel.
    * **Admin Password**: The password for the web panel.
    * **Panel Port**: The port on which the web panel will be accessible.
3.  The installer will then set up all dependencies, download the panel application, and configure the services.

### *Step 4: Access Your Panel*
After the installation is complete, the script will display the access details for your new web panel, including the URL, username, and password.

---

## 🔧 Post-Installation Management
You can manage your installation at any time by running the manager script again:

```bash
vpn_manager
```

This will open the main menu where you can:

* Uninstall the Web Panel or OpenVPN.
* View your panel's login information.
* Access the **Panel Settings** to change the username, password, or port.
* Update the web panel to the latest version.

---

## 📞 Contact & Support
* **7-Day Trial:** To receive a 7-day trial license, please visit our Telegram bot: [@eylan_licensebot](https://t.me/eylan_licensebot)
* **Purchase & Inquiries:** For purchasing a full license or setup assistance, please get in touch via Telegram: [@eylandooo](https://t.me/eylandooo)
* **Telegram Channel:** [@eylanpanel](https://t.me/eylanpanel)
