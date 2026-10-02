#!/bin/bash
# Example build pipeline for SPEC CPU 2017 benchmarks.
# For each benchmark: compile with WPD pass, generate linker script, re-link.

C=`pwd`

benches=( 500.perlbench_r 505.mcf_r 508.namd_r 510.parest_r 519.lbm_r
          520.omnetpp_r 523.xalancbmk_r 531.deepsjeng_r 541.leela_r
          544.nab_r 557.xz_r )

for i in "${benches[@]}"; do
    echo $i
    cd $C/$i/build/build_peak_mytest-m64.0000
    # make wpd -j8
    # python3 linker.py .
    # make wpd_custlink
    # ./run.sh wpd_cl large
done

for i in 525.x264_r 538.imagick_r 511.povray_r 526.blender_r; do
    echo $i
    cd $C/$i/build/build_peak_mytest-m64.0000
    # make wpd -j8 TARGET=${i##*.}
    # python3 linker.py .
    # make wpd_custlink TARGET=${i##*.}
    # ./run.sh wpd_cl large
done
