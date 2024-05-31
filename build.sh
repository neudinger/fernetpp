#/usr/bin/env sh

work_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

# rm -rf built_* build_* dist_* .external_*

declare Fernet_VERSION=${Fernet_VERSION:=$1}
export Fernet_VERSION=${Fernet_VERSION:="0.0.0.0"}

mkdir -p dist_debug_deb dist_release_deb

declare job_number=$(expr $(nproc) + 1)

set -eux &&
    cmake -B build_debug-fernet-lib --preset debug &&
    cmake --build ${work_dir}/build_debug-fernet-lib/ -j${job_number} &&
    ./build_debug-fernet-lib/Fernet.exe &&
    ctest --test-dir build_debug-fernet-lib/ --verbose 2>&1 &&
    cmake -B build_release-fernet-lib --preset release &&
    cmake --build ${work_dir}/build_release-fernet-lib/ -j${job_number} &&
    # cmake --install build_debug-fernet-lib &&
    (cd build_debug-fernet-lib && cpack -G DEB) &&
    mv dist_Fernet_debug/*.deb dist_debug_deb/ &&
    cmake -B build_release-fernet-lib --preset release &&
    # cmake --build ${work_dir}/build_release-fernet-lib -j${job_number}  --preset release &&
    cmake --build ${work_dir}/build_release-fernet-lib -j${job_number} &&
    # cmake --install build_release-fernet-lib &&
    (cd build_release-fernet-lib && cpack -G DEB) &&
    mv dist_Fernet_release/*.deb dist_release_deb/

# https://honeytreelabs.com/posts/memory-checking-unit-tests/
# ctest --test-dir build --verbose 2>&1
# ctest -E '.*_memchecked_.*' --verbose 2>&1
# ctest --test-dir build -R '.*_memchecked_.*' --verbose 2>&1
echo done
