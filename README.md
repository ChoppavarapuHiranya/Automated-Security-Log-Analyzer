\# Automated Security Log Analyzer for Detecting Suspicious Login Activities



\## 1. Project Overview



The Automated Security Log Analyzer is a Python-based cybersecurity application designed to analyze Linux and Windows security logs and identify suspicious authentication activities.



The system automates the analysis of security events that would otherwise require manual investigation. It parses authentication logs, extracts relevant information, applies detection rules, assigns severity levels, and generates an HTML analytical report.



\---



\## 2. Problem Statement



Security logs contain valuable information about failed login attempts, successful authentications, suspicious source IP addresses, and unusual login times.



Manual analysis of large amounts of security log data can be time-consuming and may cause important security events to be overlooked.



This project develops a Python application that automatically parses Linux and Windows security logs, detects suspicious authentication patterns, and generates an analytical security report.



\---



\## 3. Objectives



The main objectives of the project are:



\- Parse Linux authentication logs.

\- Parse Windows Security Event-style records.

\- Extract timestamps, usernames, IP addresses, ports, and authentication status.

\- Detect possible brute-force attacks.

\- Detect repeated authentication failures.

\- Identify suspicious source IP addresses.

\- Detect unusual login times.

\- Analyze Windows failed login events.

\- Assign severity levels to detected alerts.

\- Generate a consolidated HTML security report.

\- Demonstrate automated security log analysis using Python.



\---



\## 4. Technologies Used



\- Python 3

\- Regular Expressions

\- CSV Processing

\- HTML

\- CSS

\- Windows PowerShell

\- Visual Studio Code

\- Windows 11



\---



\## 5. Project Architecture



```text

Linux / Windows Security Logs

&#x20;           |

&#x20;           v

&#x20;      Log Parsers

&#x20;           |

&#x20;           v

&#x20;  Structured Security Events

&#x20;           |

&#x20;           v

&#x20;     Detection Engine

&#x20;           |

&#x20;    +------+------+------+

&#x20;    |      |      |      |

&#x20;    v      v      v      v

&#x20;Brute   Repeated  IP   Unusual

&#x20;Force   Failures Alert   Time

&#x20;    |      |      |      |

&#x20;    +------+------+------+

&#x20;           |

&#x20;           v

&#x20;     Severity Analysis

&#x20;           |

&#x20;           v

&#x20;    HTML Security Report

