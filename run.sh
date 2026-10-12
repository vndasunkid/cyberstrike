#!/bin/bash

pkill -f "cyberstrike web" 2>/dev/null; sleep 1
export DISPLAY=:10 && export XAUTHORITY=/home/master/.Xauthority &&export CYBERSTRIKE_SERVER_PASSWORD=admin && /home/master/code/CyberStrike/packages/cyberstrike/dist/cyberstrike-linux-x64/bin/cyberstrike web --hostname 0.0.0.0 --port 4444