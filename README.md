# NmapDetector
Attempts to detect nmap scans by looking at certain patterns


Currently have it working for a few scans, main things needed are cleanup type stuff
and fixing certain issues with scans that cannot be 100% detected just by sniffing the packet

Currently have this working well enough to use, so am not adding to it as of this moment.  The librtbtstuff api is in another repository, but contains utility functions that are dynamically loaded - moreso due to a lot of the same functions coming up between a bunch of the projects I was working on at the time.
