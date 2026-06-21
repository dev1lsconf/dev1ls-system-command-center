#!/bin/bash
systemctl --system start nftables.service
systemctl --system is-active nftables.service
