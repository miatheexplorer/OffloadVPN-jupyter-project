# OffloadVPN-jupyter-project
#Adaptive VPN Offloading Using p4

P4-based VPN offloading experiment implemented using **JupyterHub**, **Docker**, and **P4Runtime**.

This project demonstrates how programmable data planes (P4) can be used to offload VPN processing to improve network efficiency and performance.

---

## Overview

Traditional VPN processing is handled entirely by software on hosts or servers.
This project explores **offloading VPN-related packet processing to programmable network devices** using the **P4 language**.

The environment runs inside **JupyterHub containers**, making it easier to experiment with programmable networking and network simulations.

---

## Technologies Used

* **P4 Language**
* **P4Runtime**
* **JupyterHub**
* **Docker**
* **Python**
* **Mininet (for network topology simulation)**

---

## Setup

### 1. Clone the repository

```
git clone https://github.com/miatheexplorer/OffloadVPN-jupyter-project.git
cd OffloadVPN-jupyter-project
```

---

### 2. Start the environment

Make sure Docker and Docker Compose are installed.

```
docker compose up -d
```

This will start the **JupyterHub environment**.

---

### 3. Access JupyterHub

Open your browser and go to:

```
http://localhost:8000
```

Login and navigate to the **Offloading** directory to run experiments.

---

## Running the P4 Experiment

Inside the `Offloading` directory you can:

Compile the P4 program and run the network topology and controller scripts according to the Test Sheet.

The project includes:

* P4 program definitions
* runtime configuration
* controller scripts
* Mininet topology

---

## Example Files

| File                      | Description                                      |
| ------------------------- | ------------------------------------------------ |
| `Offload.p4`              | Main P4 program implementing VPN offloading      |
| `p4runtime_controller.py` | Python controller interacting with the P4 switch |
| `topology.json`           | Network topology configuration                   |
| `Makefile`                | Build and run automation                         |

---

## Research Goal

The goal of this project is to evaluate how **programmable switches can offload VPN packet processing** and improve:

* network performance
* latency
* CPU usage on host systems

---

## Author

GitHub: https://github.com/miatheexplorer

---

## License

This project is intended for **research and educational purposes**.
