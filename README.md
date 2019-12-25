# IpBlacklister
Scans an apache access.log file and evaluates if ip adresses should be blacklisted in UFW firewall with help of abuseipdb.

Add you abuseipdb api key in settings.json, and modify the access.log filepath if it's located elsewhere. 

Run `ip_blacklister.py` for a single run through or run `autorun_ip_blacklister.py` for a access.log scan every 24h at 12:00 local time. Run `make_database.py` before atempting to run IpBlacklister.

Requires python to be run as sudo due to the use of UFW.

If you use other firewall software or want lesser/tougher evaluation of each ip you can modify `ban()` and `evaluate_ip()` to fit your neeeds.

Requires python 3.6+ at least, developed under python 3.7.

To run `autorun_ip_blacklister.py` continiously after system boot you can use the provided service template `ip_blacklister.service` and modify it with your proper paths.
When modified, place `ip_blacklister.service` in `/lib/systemd/system/` Then execute:
```
sudo chmod 644 /lib/systemd/system/ip_blacklister.service
sudo systemctl daemon-reload
sudo systemctl enable ip_blacklister.service
```
Check the service status with `sudo systemctl status ip_blacklister.service` it should be active after next system boot.
