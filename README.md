# OVPN Manager: A Powerful Web Panel for OpenVPN

[![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.x-black?logo=flask)](https://flask.palletsprojects.com/)
[![Tailwind CSS](https://img.shields.io/badge/UI-Tailwind_CSS-38B2AC?logo=tailwind-css)](https://tailwindcss.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

OVPN Manager is a comprehensive, self-hosted web panel built with Flask to streamline the management of OpenVPN servers. It provides a modern, user-friendly, and feature-rich interface for managing users, resellers (sub-admins), and even multi-node deployments, turning complex server administration into a simple point-and-click experience.

This panel is designed for administrators who need granular control over user access, traffic, and server resources, all from a centralized and intuitive dashboard.

### 📸 Dashboard Preview

*(Note: Replace this with a real screenshot of your dashboard)*
![OVPN Manager Dashboard](https://cdn.imgurl.ir/uploads/d53118_.png)
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

This guide assumes you are installing on a Debian-based Linux distribution (e.g., Ubuntu 20.04+).
###  Clone the Repository
```bash
wget -q -O /root/vpn_manager.sh https://raw.githubusercontent.com/eylandoo/openvpn_webpanel_manager/main/vpn_manager.sh && chmod +x /root/vpn_manager.sh && /root/vpn_manager.sh
