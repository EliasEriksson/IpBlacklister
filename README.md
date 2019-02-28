# IpBlacklister
Scans an apache access.log file and evaluates if ip adresses should be blacklisted in UFW firewall with help of abuseipdb.

Add you abuseipdb api key in settings.json, and modefy the acces.log filepath if its located elsewhere. 

Run `ip_blacklister.py` for a single run through or run `autorun_ip_blacklister.py` for a access.log scan every 24h at 12:00 local time. Run `make_database.py` before atempting to run IpBlacklister.

Requires python to be run as sudo due to the use of UFW.

If you use other firewall software or want lesser/tougher evaluation of each ip you can modify `ban()` and `evaluate_ip()` to fit your neeeds.
