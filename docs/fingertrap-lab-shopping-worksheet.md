# Fingertrap Lab Shopping Worksheet

Prepared for: Nobode
Purpose: source the lab hardware and supporting infrastructure for the 3-zone Fingertrap environment.

## Buying rules
- Prioritize lab isolation, power control, and logging before extra peripherals.
- Favor devices that can be reimaged, power-cycled, and segmented by VLAN.
- Keep credentials, tokens, private keys, and production secrets out of this repo.
- Store only product links, SKU notes, specs, and non-sensitive procurement details here.

---

## Tier 1 — Core compute and control

### 1) x86 Ubuntu mini PC
Role: main brain, logs, Docker, tooling, orchestration
Recommended: Intel N100/N305 or Ryzen mini PC, 16–32 GB RAM, 512 GB SSD

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=Intel+N100+mini+PC
- eBay: https://www.ebay.com/sch/i.html?_nkw=Intel+N100+mini+PC

### 2) Raspberry Pi 5
Role: edge Linux node, GPIO bridge, small services
Recommended: 8 GB, official PSU, active cooling

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=Raspberry+Pi+5+8GB
- eBay: https://www.ebay.com/sch/i.html?_nkw=Raspberry+Pi+5+8GB

### 3) ESP32-S3 dev board with PSRAM
Role: Otacon front-end controller, UI, relays, LEDs
Recommended: USB-C, PSRAM, enough GPIO

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=ESP32-S3+dev+board+with+PSRAM
- eBay: https://www.ebay.com/sch/i.html?_nkw=ESP32-S3+dev+board+with+PSRAM

### 4) ESP32-S3 camera board
Role: compact vision/status capture node

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=ESP32-S3+camera+board
- eBay: https://www.ebay.com/sch/i.html?_nkw=ESP32-S3+camera+board

### 5) Kendryte K230 board
Role: vision/perception node for multi-camera work

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=Kendryte+K230+board
- eBay: https://www.ebay.com/sch/i.html?_nkw=Kendryte+K230+board

---

## Tier 2 — Network core

### 6) Managed gigabit switch with VLAN support
Role: zone segmentation, port mirroring, traffic control
Recommended: 8-port or 16-port managed gigabit switch

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=managed+gigabit+switch+vlan
- eBay: https://www.ebay.com/sch/i.html?_nkw=managed+gigabit+switch+vlan

### 7) Dedicated firewall/router
Role: isolation, policy control, logging
Recommended: pfSense/OPNsense-compatible x86 appliance

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=pfSense+appliance
- eBay: https://www.ebay.com/sch/i.html?_nkw=pfSense+appliance

### 8) Dedicated Wi-Fi access point
Role: isolated lab SSID
Recommended: VLAN-capable AP with stable firmware

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=wifi+access+point+vlan
- eBay: https://www.ebay.com/sch/i.html?_nkw=wifi+access+point+vlan

---

## Tier 3 — Power and recovery

### 9) Smart power strip / remote PDU
Role: power-cycle devices, simulate outage

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=smart+power+strip+wifi
- eBay: https://www.ebay.com/sch/i.html?_nkw=smart+power+strip+wifi

### 10) USB power switch / relay module
Role: per-device power control for test runs

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=usb+power+switch+relay
- eBay: https://www.ebay.com/sch/i.html?_nkw=usb+power+switch+relay

### 11) Relay board
Role: trigger test conditions, cut power, switch loads

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=relay+board+usb
- eBay: https://www.ebay.com/sch/i.html?_nkw=relay+board+usb

### 12) UPS
Role: keep control plane alive during power tests

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=UPS+for+mini+pc
- eBay: https://www.ebay.com/sch/i.html?_nkw=UPS+for+mini+pc

---

## Tier 4 — Evidence and storage

### 13) NAS or SSD storage node
Role: logs, packet captures, firmware images, recordings
Recommended: 1 TB+ usable storage

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=NAS+box+2+bays
- eBay: https://www.ebay.com/sch/i.html?_nkw=NAS+box+2+bays

### 14) External SSD
Role: fast artifact storage and portable evidence bundles

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=external+ssd+1tb
- eBay: https://www.ebay.com/sch/i.html?_nkw=external+ssd+1tb

### 15) High-endurance microSD cards
Role: Pi boot, cameras, fixtures

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=high+endurance+micro+sd
- eBay: https://www.ebay.com/sch/i.html?_nkw=high+endurance+micro+sd

---

## Tier 5 — Debug and instrumentation

### 16) Powered USB hub
Role: stable flashing and multi-device access

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=powered+usb+hub+usb-c
- eBay: https://www.ebay.com/sch/i.html?_nkw=powered+usb+hub+usb-c

### 17) USB-to-serial adapters
Role: flash, serial logging, recovery

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=usb+to+serial+adapter+cp2102
- eBay: https://www.ebay.com/sch/i.html?_nkw=usb+to+serial+adapter+cp2102

### 18) JTAG probe
Role: firmware debug and recovery

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=jtag+probe+esp32
- eBay: https://www.ebay.com/sch/i.html?_nkw=jtag+probe+esp32

### 19) Logic analyzer
Role: serial/I2C/SPI visibility

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=logic+analyzer+8+channel
- eBay: https://www.ebay.com/sch/i.html?_nkw=logic+analyzer+8+channel

### 20) Bench power supply
Role: controlled voltage testing and recovery

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=bench+power+supply+30v+5a
- eBay: https://www.ebay.com/sch/i.html?_nkw=bench+power+supply+30v+5a

---

## Tier 6 — Otacon interface hardware

### 21) Small display
Role: status, prompts, zone state

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=spi+tft+display+esp32
- eBay: https://www.ebay.com/sch/i.html?_nkw=spi+tft+display+esp32

### 22) Buttons / rotary encoder
Role: local control

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=rotary+encoder+button+module
- eBay: https://www.ebay.com/sch/i.html?_nkw=rotary+encoder+button+module

### 23) LEDs / RGB indicators
Role: trust state, alert state, zone state

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=ws2812b+led+module
- eBay: https://www.ebay.com/sch/i.html?_nkw=ws2812b+led+module

### 24) Speaker / buzzer / microphone
Role: offline assistant feedback

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=esp32+microphone+speaker+module
- eBay: https://www.ebay.com/sch/i.html?_nkw=esp32+microphone+speaker+module

---

## Tier 7 — Security and trust

### 25) Secure element / TPM
Role: stronger device identity and key storage

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=atecc608a+module
- eBay: https://www.ebay.com/sch/i.html?_nkw=atecc608a+module

### 26) RTC module
Role: time continuity for logs and certs

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=ds3231+rtc+module
- eBay: https://www.ebay.com/sch/i.html?_nkw=ds3231+rtc+module

### 27) Environmental sensors
Role: temperature, humidity, tamper monitoring

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=temperature+humidity+sensor+module
- eBay: https://www.ebay.com/sch/i.html?_nkw=temperature+humidity+sensor+module

---

## Tier 8 — Lab realism extras

### 28) IP camera
Role: room and bench capture

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=ip+camera+poe
- eBay: https://www.ebay.com/sch/i.html?_nkw=ip+camera+poe

### 29) Thermal camera
Role: heat profiling, board faults, power anomalies

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=thermal+camera+usb
- eBay: https://www.ebay.com/sch/i.html?_nkw=thermal+camera+usb

### 30) Label maker
Role: cable and device labeling for maintainability

Links:
- AliExpress: https://www.aliexpress.com/wholesale?SearchText=label+maker+thermal
- eBay: https://www.ebay.com/sch/i.html?_nkw=label+maker+thermal

---

## Recommended purchase order

### Phase 1 — must-have
- x86 Ubuntu mini PC
- managed switch
- firewall/router
- ESP32 Otacon board
- Raspberry Pi 5
- USB hub
- serial adapters
- power control

### Phase 2 — lab expansion
- Kendryte K230 board
- NAS / SSD storage
- display / input for Otacon
- relay control
- isolated AP
- environmental sensors

### Phase 3 — advanced ops
- JTAG
- logic analyzer
- bench PSU
- thermal camera
- secure element / RTC
- IP camera

---

## Notes for Nobode
- Keep the worksheet updated as listings change.
- Prefer non-sensitive procurement notes only.
- Add vendor, model, price, and status columns when compiling the final buying list.
- Do not store credentials, private keys, or production identifiers here.
