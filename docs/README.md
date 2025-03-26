# NetWatch Desktop App

## Purpose
A desktop application to monitor home network activity, designed for parents to manage children's online behavior. Built with PyQt 5.1.3, it works online (syncs settings) and offline (stores data locally).

## Features
- Monitor devices: List device names, IPs, MACs, and sites visited.
- Real-time and historical logs: View activity with timestamps.
- Online configuration: Web GUI to toggle monitoring and set filters.
- Offline access: Logs stored in SQLite for use without internet.
- Commercial use: Simple installer and license key system.

## Target Audience
Parents managing small home networks (2-10 devices).

## Legal Notes
- For private use only; inform household members of monitoring.
- Data stored locally unless cloud sync is enabled.

## Tech Stack
- PyQt 5.1.3: Desktop GUI
- Scapy: Network traffic capture
- Flask: Online config GUI
- SQLite: Local data storage
