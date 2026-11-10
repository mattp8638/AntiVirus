# name: Reset network stack
# description: Resets Winsock and TCP/IP and flushes DNS. A restart is needed afterwards (changes the system).
# category: Network
# platforms: windows
# timeout: 300
# Fenrir community script library: see catalogue/README.md. Reviewed before it ships.
netsh winsock reset; netsh int ip reset; ipconfig /flushdns
'Network stack reset: restart the device to finish.'
