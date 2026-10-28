#!/usr/bin/env python3
"""Run FreeRTOS lock-adapter contract tests with a host semaphore test double.
No external Python packages. Hardware tests must verify the real kernel too.
"""
import argparse
import pathlib
import signal
import subprocess
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--cc", default="cc")
args = parser.parse_args()
here = pathlib.Path(__file__).resolve().parent
root = here.parents[2]
header = (root / "arch/freertos/freertos.h.in").read_text().replace(
    "#cmakedefine UA_ARCHITECTURE_FREERTOS", "#define UA_ARCHITECTURE_FREERTOS")
with tempfile.TemporaryDirectory(prefix="ua-freertos-locks-") as tmp:
    tmp = pathlib.Path(tmp)
    (tmp / "freertos_generated.h").write_text(header)
    for static, dynamic in [(0, 1), (1, 0), (1, 1)]:
        for debug in [False, True]:
            exe = tmp / f"locks-{static}-{dynamic}-{debug}"
            flags = [f"-DconfigSUPPORT_STATIC_ALLOCATION={static}",
                     f"-DconfigSUPPORT_DYNAMIC_ALLOCATION={dynamic}"]
            flags += ["-DUA_DEBUG"] if debug else ["-DNDEBUG"]
            command = [args.cc, "-std=c11", "-D_XOPEN_SOURCE=700", "-pthread",
                       "-Wall", "-Wextra", "-Werror", "-I", str(here), "-I", str(tmp),
                       *flags, str(here / "check_locks.c"), "-o", str(exe)]
            subprocess.run(command, check=True, capture_output=True)
            subprocess.run([str(exe)], check=True, timeout=30)
            for failure in ["allocation-failure", "destroy-held", "wrong-owner"]:
                result = subprocess.run([str(exe), failure], capture_output=True, timeout=5)
                assert result.returncode == -signal.SIGABRT, (failure, result)
            print(f"PASS: static={static}, dynamic={dynamic}, debug={debug}; fatal paths")
    invalid = [(["-DconfigUSE_MUTEXES=0"], "configUSE_MUTEXES=1"),
               (["-DconfigUSE_RECURSIVE_MUTEXES=0"], "configUSE_RECURSIVE_MUTEXES=1"),
               (["-DINCLUDE_xTaskGetCurrentTaskHandle=0"], "INCLUDE_xTaskGetCurrentTaskHandle=1"),
               (["-DconfigSUPPORT_STATIC_ALLOCATION=0", "-DconfigSUPPORT_DYNAMIC_ALLOCATION=0"],
                "requires static or dynamic")]
    for flags, message in invalid:
        result = subprocess.run([args.cc, "-std=c11", "-D_XOPEN_SOURCE=700", "-pthread",
                                 "-I", str(here), "-I", str(tmp), *flags,
                                 "-fsyntax-only", str(here / "check_locks.c")],
                                capture_output=True, text=True)
        assert result.returncode != 0 and message in result.stderr, result.stderr
        print("PASS: rejects", " ".join(flags))
