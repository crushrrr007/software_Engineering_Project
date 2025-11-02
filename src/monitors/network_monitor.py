"""
Network Monitor Module
Monitors network traffic for screenshot exfiltration attempts
"""

import psutil
import time
import threading
from typing import Dict, List, Set
from datetime import datetime, timedelta
from collections import defaultdict, deque


class NetworkConnection:
    """Information about a network connection"""

    def __init__(self, pid: int, process_name: str, local_addr: tuple,
                 remote_addr: tuple, status: str, protocol: str = "TCP"):
        self.pid = pid
        self.process_name = process_name
        self.local_addr = local_addr
        self.remote_addr = remote_addr
        self.status = status
        self.protocol = protocol
        self.timestamp = datetime.now()
        self.bytes_sent = 0
        self.bytes_received = 0

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "local_address": f"{self.local_addr[0]}:{self.local_addr[1]}" if self.local_addr else "N/A",
            "remote_address": f"{self.remote_addr[0]}:{self.remote_addr[1]}" if self.remote_addr else "N/A",
            "status": self.status,
            "protocol": self.protocol,
            "timestamp": self.timestamp.isoformat(),
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received
        }


class NetworkMonitor:
    """Monitors network activity for screenshot exfiltration"""

    def __init__(self, config: Dict, logger):
        """
        Initialize the network monitor

        Args:
            config: Configuration dictionary
            logger: Logger instance
        """
        self.config = config
        self.logger = logger
        self.running = False
        self.alert_callback = None

        # Connection tracking
        self.active_connections: Dict[tuple, NetworkConnection] = {}
        self.connection_history = deque(maxlen=5000)

        # Traffic tracking (pid -> stats)
        self.traffic_stats = defaultdict(lambda: {
            "bytes_sent": 0,
            "bytes_received": 0,
            "connections": 0,
            "suspicious_ports": 0
        })

        # Bandwidth tracking (per process, per minute)
        self.bandwidth_tracker = defaultdict(lambda: deque(maxlen=60))

        # Configuration
        self.suspicious_ports = set(config.get("suspicious_ports", [
            4444, 5555, 6666, 8080, 8888, 9999
        ]))
        self.monitored_protocols = set(config.get("monitored_protocols", ["TCP", "UDP"]))
        self.large_transfer_threshold = config.get("large_transfer_threshold", 1048576)  # 1MB
        self.bandwidth_threshold = config.get("bandwidth_threshold", 5242880)  # 5MB/min

        # Whitelist
        self.whitelist_ips = self._parse_whitelist(config.get("whitelist", []))
        
        # Trusted processes with custom bandwidth thresholds
        self.trusted_processes = config.get("trusted_processes", {})
        # Convert to lowercase for case-insensitive matching
        self.trusted_processes = {k.lower(): v for k, v in self.trusted_processes.items()}

    def _parse_whitelist(self, whitelist: List[str]) -> Set[str]:
        """
        Parse whitelist (expand localhost variations)

        Args:
            whitelist: List of whitelisted IPs/patterns

        Returns:
            Set of whitelisted IPs
        """
        ips = set()
        for entry in whitelist:
            if entry in ["localhost", "127.0.0.1", "::1"]:
                ips.add("127.0.0.1")
                ips.add("::1")
            else:
                ips.add(entry)
        return ips

    def start(self):
        """Start the network monitor"""
        if self.running:
            self.logger.warning("Network monitor already running")
            return

        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        self.logger.info("Network monitor started")

    def stop(self):
        """Stop the network monitor"""
        self.running = False
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join(timeout=5)
        self.logger.info("Network monitor stopped")

    def set_alert_callback(self, callback):
        """Set callback function for alerts"""
        self.alert_callback = callback

    def _monitor_loop(self):
        """Main monitoring loop"""
        # Get initial network counters
        prev_counters = {}
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    io = proc.io_counters()
                    prev_counters[proc.info['pid']] = {
                        'read_bytes': io.read_bytes,
                        'write_bytes': io.write_bytes
                    }
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except:
            pass

        while self.running:
            try:
                self._scan_connections()
                self._track_bandwidth(prev_counters)
                self._analyze_traffic()
                time.sleep(5)
            except Exception as e:
                self.logger.error(f"Error in network monitor loop: {e}", exc_info=True)
                time.sleep(5)

    def _scan_connections(self):
        """Scan active network connections"""
        try:
            connections = psutil.net_connections(kind='inet')

            current_keys = set()

            for conn in connections:
                try:
                    # Skip connections without process info
                    if not conn.pid:
                        continue

                    # Get process name
                    try:
                        proc = psutil.Process(conn.pid)
                        process_name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        process_name = "Unknown"

                    # Create connection key
                    conn_key = (conn.pid, conn.laddr, conn.raddr if conn.raddr else None)
                    current_keys.add(conn_key)

                    # Check if already tracked
                    if conn_key not in self.active_connections:
                        net_conn = NetworkConnection(
                            pid=conn.pid,
                            process_name=process_name,
                            local_addr=conn.laddr,
                            remote_addr=conn.raddr,
                            status=conn.status,
                            protocol=conn.type.name if hasattr(conn.type, 'name') else "TCP"
                        )
                        self.active_connections[conn_key] = net_conn
                        self.connection_history.append(net_conn)

                        # Analyze new connection
                        self._analyze_connection(net_conn)

                except Exception as e:
                    self.logger.debug(f"Error processing connection: {e}")
                    continue

            # Remove closed connections
            closed_keys = set(self.active_connections.keys()) - current_keys
            for key in closed_keys:
                del self.active_connections[key]

        except Exception as e:
            self.logger.error(f"Error scanning connections: {e}")

    def _analyze_connection(self, conn: NetworkConnection):
        """
        Analyze a network connection for suspicious activity

        Args:
            conn: NetworkConnection object
        """
        # Skip localhost connections
        if conn.remote_addr and conn.remote_addr[0] in self.whitelist_ips:
            return

        # Check for suspicious ports
        if conn.remote_addr and conn.remote_addr[1] in self.suspicious_ports:
            self.traffic_stats[conn.pid]["suspicious_ports"] += 1
            self._create_alert(
                conn,
                "suspicious_port",
                f"Connection to suspicious port detected: {conn.process_name} -> {conn.remote_addr[0]}:{conn.remote_addr[1]}"
            )

        # Track connection count
        self.traffic_stats[conn.pid]["connections"] += 1

    def _track_bandwidth(self, prev_counters: Dict):
        """
        Track bandwidth usage per process

        Args:
            prev_counters: Previous I/O counters
        """
        try:
            current_time = time.time()

            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    pid = proc.info['pid']
                    io = proc.io_counters()

                    if pid in prev_counters:
                        # Calculate bytes sent/received since last check
                        bytes_sent = io.write_bytes - prev_counters[pid]['write_bytes']
                        bytes_received = io.read_bytes - prev_counters[pid]['read_bytes']

                        # Update stats
                        self.traffic_stats[pid]["bytes_sent"] += bytes_sent
                        self.traffic_stats[pid]["bytes_received"] += bytes_received

                        # Track bandwidth over time
                        self.bandwidth_tracker[pid].append({
                            'timestamp': current_time,
                            'bytes_sent': bytes_sent,
                            'bytes_received': bytes_received
                        })

                    # Update prev counters
                    prev_counters[pid] = {
                        'read_bytes': io.read_bytes,
                        'write_bytes': io.write_bytes
                    }

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        except Exception as e:
            self.logger.error(f"Error tracking bandwidth: {e}")

    def _analyze_traffic(self):
        """Analyze traffic patterns for suspicious activity"""
        try:
            cutoff_time = time.time() - 60  # Last minute

            for pid, bandwidth_deque in self.bandwidth_tracker.items():
                # Calculate total bytes sent in last minute
                recent_bytes_sent = sum(
                    entry['bytes_sent']
                    for entry in bandwidth_deque
                    if entry['timestamp'] > cutoff_time
                )

                # Get process name and check if it's trusted
                try:
                    proc = psutil.Process(pid)
                    process_name = proc.name()
                    process_name_lower = process_name.lower()
                    
                    # Get threshold for this process (trusted processes may have higher thresholds)
                    threshold = self.trusted_processes.get(process_name_lower, self.bandwidth_threshold)
                    
                    # Alert on high bandwidth (use process-specific threshold if trusted, otherwise default)
                    if recent_bytes_sent > threshold:
                        self._create_alert(
                            None,
                            "high_bandwidth",
                            f"High outbound bandwidth detected: {process_name} (PID: {pid}) sent {recent_bytes_sent / 1048576:.2f} MB in last minute",
                            pid=pid,
                            process_name=process_name
                        )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        except Exception as e:
            self.logger.error(f"Error analyzing traffic: {e}")

    def _create_alert(self, conn: NetworkConnection, alert_type: str, message: str,
                     pid: int = None, process_name: str = None):
        """
        Create an alert for suspicious network activity

        Args:
            conn: NetworkConnection object (can be None)
            alert_type: Type of alert
            message: Alert message
            pid: Process ID (if conn is None)
            process_name: Process name (if conn is None)
        """
        severity_map = {
            "suspicious_port": "high",
            "high_bandwidth": "high",
            "large_transfer": "medium",
            "unusual_destination": "medium"
        }

        alert = {
            "timestamp": datetime.now(),
            "type": "network_monitor",
            "severity": severity_map.get(alert_type, "medium"),
            "alert_type": alert_type,
            "message": message,
            "mitre_technique": "T1041"  # Exfiltration Over C2 Channel
        }

        if conn:
            alert["connection"] = conn.to_dict()
        elif pid:
            alert["process"] = {
                "pid": pid,
                "name": process_name or "Unknown"
            }

        self.logger.warning(f"[Network Monitor] {message}")

        if self.alert_callback:
            self.alert_callback(alert)

    def get_statistics(self) -> Dict:
        """Get network monitoring statistics"""
        total_connections = len(self.connection_history)
        active_connections = len(self.active_connections)

        # Calculate total traffic
        total_sent = sum(stats["bytes_sent"] for stats in self.traffic_stats.values())
        total_received = sum(stats["bytes_received"] for stats in self.traffic_stats.values())

        # Top talkers
        top_senders = sorted(
            [(pid, stats["bytes_sent"]) for pid, stats in self.traffic_stats.items()],
            key=lambda x: x[1],
            reverse=True
        )[:10]

        return {
            "total_connections_tracked": total_connections,
            "active_connections": active_connections,
            "total_bytes_sent": total_sent,
            "total_bytes_received": total_received,
            "top_senders": [{"pid": pid, "bytes_sent": bytes_sent}
                          for pid, bytes_sent in top_senders],
            "monitoring_since": datetime.now()
        }

    def get_active_connections(self) -> List[Dict]:
        """Get list of active connections"""
        return [conn.to_dict() for conn in self.active_connections.values()]

    def get_process_traffic(self, pid: int) -> Dict:
        """
        Get traffic statistics for a process

        Args:
            pid: Process ID

        Returns:
            Traffic statistics
        """
        return self.traffic_stats.get(pid, {
            "bytes_sent": 0,
            "bytes_received": 0,
            "connections": 0,
            "suspicious_ports": 0
        })
