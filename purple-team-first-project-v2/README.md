# purple-team-toolkit

my first purple team project. made this while learning SOC stuff.

### what is this?
basically a small log analyzer. i was learning how blue team detects attacks, so i made this.
it checks auth.log type files for brute force, sqli, xss etc and makes a report.

i know its basic right now, but will improve it later.

### how i made it
- started with just brute force detection
- then added sqli and xss patterns from tryhackme notes
- added report generation at the end

### how to run

```
pip install -r requirements.txt
python main.py
```

thats it. check reports folder after running.

### folder structure
```
.
├── main.py
├── config.json
├── sample_logs/
│   └── auth.log
├── reports/
└── README.md
```

### sample output
```
[ALERT] SQL Injection at Line 8
[CRITICAL] Brute Force from 192.168.1.10 - 6 fails
```

### what i learned
- how to parse logs with regex
- how attackers try sqli like ' OR 1=1 --
- how SOC analysts make IOC reports

### todo
- [ ] add more attack patterns
- [ ] make it work with json logs also
- [ ] add colors in terminal

### about me
learning purple team / SOC. 14yo, from India. trying to get into cybersecurity.
this is my first repo, more coming soon.

---

if you are also learning, feel free to fork and use it.
