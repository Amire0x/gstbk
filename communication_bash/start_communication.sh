#!/bin/bash

echo "start communication now"

gnome-terminal -- bash -c "./proxy.sh; exec bash" &

sleep 2

gnome-terminal -- bash -c "./node1.sh; exec bash" &

sleep 2

gnome-terminal -- bash -c "./node2.sh; exec bash" &

sleep 2

gnome-terminal -- bash -c "./node3.sh; exec bash" &

sleep 2

gnome-terminal -- bash -c "./node4.sh; exec bash" &



