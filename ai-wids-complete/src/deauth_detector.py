#!/usr/bin/env python3
"""
===============================================================================
AI-WIDS Deauthentication Attack Detector
===============================================================================
Purpose: Detect IEEE 802.11 Deauthentication and Disassociation flood attacks
         in real-time using a sliding window counter approach.

Attack Types Detected:
  - Deauth Flood   : type=0, subtype=12 (forces clients off legitimate AP)
  - Disassoc Flood : type=0, subtype=10 (forces clients to re-associate)

How it works:
  For each packet, we check if it is a deauth or disassoc management frame.
  We maintain a per-BSSID sliding window of timestamps.
  If the count within the window exceeds a threshold, we raise an alert.
  Broadcast deauths (to ff:ff:ff:ff:ff:ff) are weighted more heavily as
  they affect ALL clients simultaneously and are a stronger attack indicator.
===============================================================================
"""

# ===========================
# IMPORTS
# ===========================
import time                                          # For timestamping sliding window entries
from collections import defaultdict, deque           # Efficient data structures for per-BSSID tracking
from datetime import datetime                        # For human-readable alert timestamps
import colorama                                      # For colored terminal output
from colorama import Fore, Style, Back               # Specific color imports
colorama.init(autoreset=True)                        # Auto-reset colors after each print

# ===========================
# CONFIGURATION / THRESHOLDS
# ===========================
DEAUTH_WINDOW_SECONDS  = 5    # Sliding time window in seconds to count frames
DEAUTH_THRESHOLD       = 10   # Number of deauth frames in window to trigger alert
DISASSOC_THRESHOLD     = 10   # Number of disassoc frames in window to trigger alert
BROADCAST_WEIGHT       = 2    # Multiplier applied to broadcast deauths (more dangerous)
MAX_ALERT_HISTORY      = 100  # Maximum number of alerts to keep in memory


class DeauthDetector:
    """
    Sliding-window deauthentication and disassociation flood detector.

    Usage:
        detector = DeauthDetector()
        alert = detector.process_packet(pkt)  # pkt is a Scapy packet
        if alert:
            print(alert)
    """

    def __init__(self):
        # Per-sender BSSID sliding window of timestamps for deauth frames
        self.deauth_times   = defaultdict(deque)    # { bssid: deque([t1, t2, ...]) }
        # Per-sender BSSID sliding window of timestamps for disassoc frames
        self.disassoc_times = defaultdict(deque)    # { bssid: deque([t1, t2, ...]) }
        # Rolling history of generated alerts
        self.alert_history  = deque(maxlen=MAX_ALERT_HISTORY)
        # Counters for dashboard stats
        self.total_deauth_frames   = 0              # Total deauth frames seen
        self.total_disassoc_frames = 0              # Total disassoc frames seen
        self.total_alerts          = 0              # Total alerts triggered

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------

    def process_packet(self, pkt):
        """
        Analyse a single Scapy packet for deauth/disassoc attack indicators.

        Args:
            pkt: A Scapy packet object (must have a Dot11 layer to be relevant)

        Returns:
            dict  - alert payload if an attack is detected
            None  - if no attack is detected
        """
        from scapy.all import Dot11  # Import here to avoid circular imports at module level

        # Ignore packets that are not 802.11 frames
        if not pkt.haslayer(Dot11):
            return None

        dot11    = pkt.getlayer(Dot11)
        fc_type    = dot11.type     # 0 = management, 1 = control, 2 = data
        fc_subtype = dot11.subtype  # 12 = deauth, 10 = disassoc

        # We only care about management frames (type 0)
        if fc_type != 0:
            return None

        now  = time.time()                                       # Current epoch timestamp
        bssid = dot11.addr2 or "00:00:00:00:00:00"             # Sender MAC (addr2 = transmitter)
        dst   = dot11.addr1 or "ff:ff:ff:ff:ff:ff"             # Destination MAC (addr1 = receiver)
        is_broadcast = (dst.lower() == "ff:ff:ff:ff:ff:ff")    # True if sent to all clients

        # --- Deauthentication frame (subtype 12) ---
        if fc_subtype == 12:
            self.total_deauth_frames += 1
            window = self.deauth_times[bssid]
            window.append(now)
            self._prune_window(window, now)

            # Weight broadcast frames more heavily
            weighted_count = len(window) * (BROADCAST_WEIGHT if is_broadcast else 1)

            if weighted_count >= DEAUTH_THRESHOLD:
                return self._create_alert(
                    attack_type   = "DEAUTH_FLOOD",
                    bssid         = bssid,
                    dst           = dst,
                    frame_count   = len(window),
                    weighted_count= weighted_count,
                    is_broadcast  = is_broadcast,
                )

        # --- Disassociation frame (subtype 10) ---
        elif fc_subtype == 10:
            self.total_disassoc_frames += 1
            window = self.disassoc_times[bssid]
            window.append(now)
            self._prune_window(window, now)

            weighted_count = len(window) * (BROADCAST_WEIGHT if is_broadcast else 1)

            if weighted_count >= DISASSOC_THRESHOLD:
                return self._create_alert(
                    attack_type   = "DISASSOC_FLOOD",
                    bssid         = bssid,
                    dst           = dst,
                    frame_count   = len(window),
                    weighted_count= weighted_count,
                    is_broadcast  = is_broadcast,
                )

        return None  # No attack detected for this packet

    def get_stats(self):
        """
        Return a summary dictionary of detection statistics for the dashboard.

        Returns:
            dict with keys: total_deauth_frames, total_disassoc_frames, total_alerts
        """
        return {
            'total_deauth_frames'  : self.total_deauth_frames,
            'total_disassoc_frames': self.total_disassoc_frames,
            'total_deauth_alerts'  : self.total_alerts,
        }

    def get_recent_alerts(self, n=10):
        """
        Return the n most recent deauth/disassoc alerts.

        Args:
            n (int): Number of alerts to return

        Returns:
            list of alert dicts, newest first
        """
        alerts = list(self.alert_history)
        return list(reversed(alerts))[:n]

    # ------------------------------------------------------------------
    # PRIVATE HELPERS
    # ------------------------------------------------------------------

    def _prune_window(self, window, now):
        """
        Remove timestamps from the left of the deque that fall outside
        the current sliding window (older than DEAUTH_WINDOW_SECONDS).

        Args:
            window (deque): The per-BSSID timestamp deque
            now    (float): Current epoch time
        """
        while window and (now - window[0]) > DEAUTH_WINDOW_SECONDS:
            window.popleft()  # Drop expired entry from the left

    def _create_alert(self, attack_type, bssid, dst, frame_count, weighted_count, is_broadcast):
        """
        Build a standardised alert dictionary and record it in history.

        Args:
            attack_type    (str):  'DEAUTH_FLOOD' or 'DISASSOC_FLOOD'
            bssid          (str):  Sender MAC address
            dst            (str):  Destination MAC address
            frame_count    (int):  Raw number of frames in window
            weighted_count (int):  Weighted frame count (broadcast multiplier applied)
            is_broadcast   (bool): True if target was broadcast address

        Returns:
            dict: The alert payload
        """
        self.total_alerts += 1  # Increment alert counter

        alert = {
            'type'          : attack_type,                          # Attack classification
            'bssid'         : bssid,                                # Attacking sender MAC
            'target'        : dst,                                  # Target MAC (or broadcast)
            'is_broadcast'  : is_broadcast,                         # True = all clients targeted
            'frame_count'   : frame_count,                          # Frames in sliding window
            'weighted_count': weighted_count,                       # Weighted count used for threshold
            'window_seconds': DEAUTH_WINDOW_SECONDS,                # Window size for context
            'timestamp'     : datetime.now().isoformat(),           # ISO timestamp of alert
            'time'          : datetime.now().strftime('%H:%M:%S'),  # Human-readable time
            'severity'      : 'HIGH',                               # All deauth floods are HIGH
        }

        self.alert_history.append(alert)  # Store in rolling history

        # Terminal output for operator awareness
        target_label = "BROADCAST (all clients)" if is_broadcast else dst
        print(
            f"{Fore.RED}⚡ [{attack_type}]{Style.RESET_ALL} "
            f"Sender: {Fore.YELLOW}{bssid}{Style.RESET_ALL} → "
            f"Target: {Fore.YELLOW}{target_label}{Style.RESET_ALL} | "
            f"Frames in {DEAUTH_WINDOW_SECONDS}s window: {Fore.RED}{frame_count}{Style.RESET_ALL} "
            f"(weighted: {weighted_count})"
        )

        return alert
