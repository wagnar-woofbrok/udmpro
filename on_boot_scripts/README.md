# Setup boostchicken on_boot for udm-pro

## 1. Install udm-boot package
```
ssh into udmpro
unifi-os shell

curl -L https://udm-boot.boostchicken.dev -o udm-boot_1.0.5_all.deb
dpkg -i udm-boot_1.0.5_all.deb
systemctl enable udm-boot
exit
```

## 2. on_boot scripts

Copy any shell scripts you want to run to /mnt/data/on_boot.d and make sure they are executable and have the correct shebang (#!/bin/sh) and extension (.sh).



