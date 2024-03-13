#!/bin/bash

cd /home/arlo/gs_tbk/gs_tbk_version2_6

cargo 'test' '--package' 'intergration_test' '--lib' '--' 'node::node2::node2::test' '--exact' '--nocapture'
