#!/bin/bash

cd /home/arlo/gs_tbk/gs_tbk_version2_6

cargo 'test' '--package' 'intergration_test' '--lib' '--' 'node::node4::node4::test' '--exact' '--nocapture'
