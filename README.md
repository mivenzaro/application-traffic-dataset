\# Application Traffic Fingerprinting Dataset



This repository contains encrypted network traffic traces collected for application fingerprinting experiments.



\## Data Collection Setup



Traffic was captured using Wireshark on a laptop while a smartphone connected to the same Wi-Fi network generated application traffic.



To minimize background noise:

\- notifications were disabled

\- background applications were closed

\- each application was executed independently



Each capture lasted approximately \*\*90 seconds\*\*.



\## Applications Captured



The dataset contains traffic traces from the following applications:



\- Amazon

\- Hulu

\- Instagram

\- LinkedIn

\- Ludo

\- Maps

\- PlayStore

\- Substack

\- WhatsApp

\- YouTube



Each trace is stored as a `.pcapng` file.



\## File Structure

amazon\_trace1.pcapng

hulu\_trace1.pcapng

instagram\_trace1.pcapng

linkedin\_trace1.pcapng

ludo\_trace1.pcapng

maps\_trace1.pcapng

playstore\_trace1.pcapng

substack\_trace1.pcapng

whatsapp\_trace1.pcapng

youtube\_trace1.pcapng





\## Dataset Size



\- 10 traffic traces

\- ~689 MB total

\- ~90 seconds per capture



\## Purpose



This dataset was collected to demonstrate the feasibility of \*\*application fingerprinting on encrypted traffic\*\*, where machine learning models attempt to identify applications based on network metadata such as packet sizes and timing patterns.



Although the payloads are encrypted using TLS, observable metadata can still reveal application behavior.



