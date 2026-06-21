#!/bin/bash
systemctl --system is-active nftables.service
systemctl --system status nftables.service 2>&1 | tail -15
echo "---RULES---"
nft list ruleset 2>&1 | head -30
