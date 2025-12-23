# AI-Driven Network Intrusion Detection System (NIDS)

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.0%2B-green)
![Status](https://img.shields.io/badge/Status-Active-success)

## Project Overview
The **AI-Driven NIDS** is a real-time security tool designed to detect network anomalies and cyber threats (DoS, Port Scanning) using a hybrid approach of **Machine Learning (Random Forest)** and **Heuristic Analysis**. It features a live "Hacker-Style" dashboard that visualizes traffic, flags malicious packets, and tracks attacker Geo-Location.

## Key Features
* **Live Traffic Monitoring:** Real-time packet visualization using Flask & WebSockets.
* **Hybrid Detection Engine:** Combines Rule-Based logic (for speed) and ML (for complex anomaly detection).
* **Geo-Location Tracking:** Automatically resolves attacker IPs to physical countries/cities.
* **Automated Forensics:** One-click export of capture data to **PDF** and **CSV** reports.
* **Responsive Dashboard:** Dark-mode UI optimized for Desktop, Tablet, and Mobile.

## Tech Stack
* **Backend:** Python, Flask, Scapy, Socket.IO
* **Frontend:** HTML5, Bootstrap 5, JavaScript
* **Database:** MongoDB Atlas (Cloud)
* **Machine Learning:** Scikit-Learn (Random Forest Classifier)



