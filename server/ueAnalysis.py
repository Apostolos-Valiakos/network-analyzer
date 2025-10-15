import pyshark
import json
from collections import defaultdict
import asyncio # Import asyncio for event loop management

def initialize_analysis_for_ue(filepath):
    """
    Initializes a pyshark capture for UE-specific analysis from the given filepath.
    Ensures an asyncio event loop is available in the current thread for pyshark operations.
    
    Args:
        filepath (str): The path to the PCAP file.
        
    Returns:
        list: A list of dictionaries, where each dictionary contains extracted UE information.
    """
    # Ensure an asyncio event loop exists for the current thread.
    # pyshark uses asyncio internally, and Flask's request threads might not have one by default.
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError: # If no event loop is running, create a new one
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
    packets_data = []
    capture = None # Initialize capture to None for proper cleanup

    try:
        capture = pyshark.FileCapture(filepath)

        # Parse all packets and extract fields into a structured dictionary format
        for pkt in capture:
            pkt_info = {
                "packet_number": pkt.number,
                "layers": []
            }
            for layer in pkt.layers:
                layer_info = {
                    "layer_name": layer.layer_name,
                    "fields": {}
                }
                for field_name in layer.field_names:
                    try:
                        # Get the field value from the pyshark layer
                        layer_info["fields"][field_name] = layer.get_field(field_name)
                    except AttributeError:
                        # Some fields might not be present in all packets or layers,
                        # gracefully skip if get_field raises an AttributeError.
                        pass
                pkt_info["layers"].append(layer_info)
            packets_data.append(pkt_info)
            
    except Exception as e:
        print(f"Error during pyshark capture in initialize_analysis_for_ue: {e}")
        # Optionally, you might want to return an empty list or raise a custom exception here
        return []
    finally:
        # Always ensure the capture object is closed to release system resources (TShark process)
        if capture:
            capture.close() 

    with open('./uploads/all_packets.json', 'w') as f:
        json.dump(packets_data, f, indent=2)

    # After parsing with pyshark, extract the specific UE information
    ue_data = extract_ue_info(packets_data) 
    return ue_data # Return the extracted UE data


def extract_ue_info(packets_data):
    """
    Extracts specific UE-related information from a list of structured packet dictionaries.
    This function processes the already parsed packet data to find relevant UE fields.
    
    Args:
        packets_data (list): A list of dictionaries, each representing a packet's layers and fields.
        
    Returns:
        list: A list of dictionaries, where each dictionary represents a UE session found.
    """
    ue_packets = []

    for pkt in packets_data:
        ue_info = {}
        found_ue_ip = False # Flag to indicate if a UE IP trigger has been found in the current packet

        for layer in pkt["layers"]:
            fields = layer["fields"]

            # Check for 'ue_ip_addr_ipv4' as a primary indicator to process the packet for UE info
            if not found_ue_ip:
                found_ue_ip = any("ue_ip_addr_ipv4" in k for k in fields)

            if not found_ue_ip:
                continue # If no UE IP trigger, move to the next layer or packet

            # Iterate through the fields of the current layer and extract common 5G UE-related fields
            # The .lower() is used for case-insensitive matching of field names.
            for key, value in fields.items():
                if "ue_ip_addr_ipv4" in key:
                    ue_info["ue_ip_addr_ipv4"] = value
                if "node_id_ipv4" in key:
                    ue_info["node_id_ipv4"] = value
                if "s_nssai_sst_sst" in key:
                    ue_info["s_nssai_sst_sst"] = value
                if "s_nssai_sst_sd" in key:
                    ue_info["s_nssai_sst_sd"] = value
                if "imsi" in key.lower():
                    ue_info["imsi"] = value
                if "guti" in key.lower():
                    ue_info["guti"] = value
                if "mcc" in key.lower():
                    ue_info["mcc"] = value
                if "mnc" in key.lower():
                    ue_info["mnc"] = value
                if "apn" in key.lower():
                    ue_info["apn"] = value
                if "dnn" in key.lower():
                    ue_info["dnn"] = value
                if "pdu_session_type" in key.lower():
                    ue_info["pdu_session_type"] = value

        if found_ue_ip:
            # If UE info was successfully identified and collected for this packet,
            # add its original packet number and append it to the results list.
            ue_info["packet_number"] = pkt["packet_number"]
            ue_packets.append(ue_info)
    return ue_packets # Return the complete list of extracted UE packets

