#!/bin/bash

cd /home/arlo/gs_tbk/gs_tbk_version2_6

cargo 'test' '--package' 'intergration_test' '--lib' '--' 'proxy::proxy_node::test' '--exact' '--nocapture'
