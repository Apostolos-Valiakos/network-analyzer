import asyncio
import websockets
import json
import base64
import threading
import sys

# Network monitoring imports
from scapy.all import sniff
from scapy.all import Packet

# System and network information imports
import psutil
import socket

# --- Configuration ---
WS_HOST = "0.0.0.0"
WS_PORT = 5002
# NOTE: This variable is updated by the 'SET_INTERFACE' command
interface = "enp0s3"
# Filter out traffic to/from the WebSocket server itself (port 5001)
bpf_filter = f"not port {WS_PORT}"

# Global state to manage capture activity
CAPTURE_ACTIVE = threading.Event()
# Start paused, waiting for client command
CAPTURE_ACTIVE.clear()

# Global reference to the main asyncio event loop
ASYNCIO_LOOP = None
# Global set to track all connected WebSocket clients
CONNECTED_CLIENTS = set()

# Lock for managing concurrent access to capture state
state_lock = threading.Lock()


# ----------------------------------------------------
## 💻 Network Interface Information Function
# ----------------------------------------------------
def get_network_interfaces_psutil():
    """Retrieves information about all network interfaces using psutil."""
    interfaces = {}
    addresses = psutil.net_if_addrs()

    for iface_name, addrs in addresses.items():
        interface_info = {
            "IP Address": None,
            "Netmask": None,
            "Broadcast IP": None,
            "MAC Address": None,
        }

        for addr in addrs:
            if addr.family == socket.AF_INET:  # IPv4
                interface_info["IP Address"] = addr.address
                interface_info["Netmask"] = addr.netmask
                interface_info["Broadcast IP"] = addr.broadcast
            elif addr.family == socket.AF_PACKET:  # MAC/Hardware Address
                interface_info["MAC Address"] = addr.address

        if any(interface_info.values()):
            interfaces[iface_name] = interface_info

    return interfaces


# ----------------------------------------------------
## 📢 Message Broadcast Functions
# ----------------------------------------------------
def broadcast_status(status_message):
    """Sends a status message to all connected clients."""
    global ASYNCIO_LOOP
    if not ASYNCIO_LOOP:
        print("Error: Asyncio loop not initialized for broadcast.", file=sys.stderr)
        return

    status_payload = json.dumps({"type": "STATUS", "status": status_message})
    clients_to_notify = list(CONNECTED_CLIENTS)

    for client in clients_to_notify:
        try:
            asyncio.run_coroutine_threadsafe(client.send(status_payload), ASYNCIO_LOOP)
        except Exception as e:
            pass

    print(f"Broadcast: {status_message}")


def packet_callback(pkt: Packet):
    """Called by Scapy's sniff function to process and send a packet."""
    global ASYNCIO_LOOP
    if not CAPTURE_ACTIVE.is_set() or not ASYNCIO_LOOP:
        return

    try:
        raw_packet_bytes = bytes(pkt)
        base64_packet = base64.b64encode(raw_packet_bytes).decode("utf-8")

        packet_payload = json.dumps({"type": "PACKET_DATA", "packet": base64_packet})

        clients_to_notify = list(CONNECTED_CLIENTS)

        for client in clients_to_notify:
            asyncio.run_coroutine_threadsafe(client.send(packet_payload), ASYNCIO_LOOP)

    except Exception as e:
        pass


# ----------------------------------------------------
## 🕵️ Sniffer Management
# ----------------------------------------------------
def run_sniffer_blocking():
    """The synchronous function that Scapy's sniff blocks on."""
    # NOTE: Scapy must be restarted for interface changes to take effect.
    print(f"Sniffer execution started in asyncio executor on interface: {interface}")
    try:
        sniff(iface=interface, filter=bpf_filter, prn=packet_callback, store=0)
    except Exception as e:
        # This error often occurs if the interface is changed while sniff is blocking.
        print(f"Scapy Sniffing Error on {interface}: {e}", file=sys.stderr)
    finally:
        print(f"Sniffer execution stopped for interface: {interface}.")


# ----------------------------------------------------
## 🌐 WebSocket Server Handlers
# ----------------------------------------------------
async def handle_client(websocket):
    """Manages the connection, registration, and incoming control messages."""
    global interface
    print(f"Client connected from {websocket.remote_address}")
    CONNECTED_CLIENTS.add(websocket)

    current_status = "STARTED" if CAPTURE_ACTIVE.is_set() else "STOPPED"
    # Report the current interface on connect
    await websocket.send(
        json.dumps(
            {
                "type": "STATUS",
                "status": f"Capture is currently {current_status}",
                "current_interface": interface,
            }
        )
    )

    try:
        async for message in websocket:
            try:
                payload = json.loads(message)
                command = payload.get("command")

                if command == "STOP_CAPTURE":
                    with state_lock:
                        if CAPTURE_ACTIVE.is_set():
                            print("Received STOP_CAPTURE command. Pausing capture...")
                            CAPTURE_ACTIVE.clear()
                            broadcast_status("CAPTURE_STOPPED")

                elif command == "START_CAPTURE":
                    with state_lock:
                        if not CAPTURE_ACTIVE.is_set():
                            print(
                                f"Received START_CAPTURE command. Resuming capture on {interface}..."
                            )
                            CAPTURE_ACTIVE.set()
                            broadcast_status("CAPTURE_STARTED")

                elif command == "GET_INTERFACES":
                    print("Received GET_INTERFACES command. Sending interface list...")
                    interface_data = get_network_interfaces_psutil()
                    response_payload = json.dumps(
                        {
                            "type": "INTERFACE_LIST",
                            "interfaces": interface_data,
                            "current_interface": interface,
                        }
                    )
                    await websocket.send(response_payload)

                elif command == "SET_INTERFACE":  # <--- DYNAMIC INTERFACE SETTING
                    new_interface = payload.get("interface")

                    if not new_interface:
                        await websocket.send(
                            json.dumps(
                                {
                                    "type": "ERROR",
                                    "message": "SET_INTERFACE requires 'interface' parameter.",
                                }
                            )
                        )
                        continue

                    # CRITICAL: Check if capture is running
                    if CAPTURE_ACTIVE.is_set():
                        await websocket.send(
                            json.dumps(
                                {
                                    "type": "ERROR",
                                    "message": "Cannot change interface while capture is running. Please STOP_CAPTURE first.",
                                }
                            )
                        )
                        print("Interface change failed: Capture is active.")
                        continue

                    # Update the global variable and notify
                    interface = new_interface
                    success_message = f"Capture interface set to: {interface}. **NOTE: You must restart the sniffer process for this change to take effect.**"
                    print(success_message)

                    await websocket.send(
                        json.dumps(
                            {
                                "type": "STATUS",
                                "status": success_message,
                                "current_interface": interface,
                            }
                        )
                    )

            except json.JSONDecodeError:
                pass
            except Exception as e:
                print(f"Error processing client message: {e}")

    except websockets.exceptions.ConnectionClosedOK:
        print(f"Client disconnected gracefully: {websocket.remote_address}")
    except websockets.exceptions.ConnectionClosedError as e:
        pass
    finally:
        print(f"Client handler cleanup for {websocket.remote_address}")
        CONNECTED_CLIENTS.discard(websocket)


async def main():
    """Starts the WebSocket server and the sniffer task."""
    global ASYNCIO_LOOP
    ASYNCIO_LOOP = asyncio.get_running_loop()

    asyncio.create_task(asyncio.to_thread(run_sniffer_blocking))
    print(f"Scapy sniffer task scheduled on initial interface: {interface}.")

    # websockets >= 14 uses serve() as an async context manager the same way,
    # but requires process_request=None to disable the built-in origin check
    # that rejects browser connections whose Origin differs from the host header.
    async with websockets.serve(
        handle_client,
        WS_HOST,
        WS_PORT,
        process_request=None,
    ):
        print(f"WebSocket server listening on ws://{WS_HOST}:{WS_PORT}")
        await asyncio.Future()


# --- Main Execution ---
if __name__ == "__main__":
    try:
        print("Starting Network Publisher...")
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nPublisher stopped by user (KeyboardInterrupt).")
    except Exception as e:
        print(f"An error occurred in the main loop: {e}")
    finally:
        print("Exiting ws_publisher.py.")
