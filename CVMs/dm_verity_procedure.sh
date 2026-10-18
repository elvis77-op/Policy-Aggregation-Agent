#!/bin/bash

set -euo pipefail

# dm-verity TDVM procedure.
# define the following variables in your environment before running this script:
TACVM_ROOT=
TD_IMG=
VERITY_TREE=
ROOT_HASH_FILE=
INITRD=
KERNEL=
SERIAL_LOG=
SSH_PORT=

usage() {
    cat <<EOF
Usage: $0 <action>

Actions:
  check              Check the prepared dm-verity boot artifacts
  build-initramfs    Rebuild the dm-verity initramfs
  start              Start the TDVM with dm-verity protection
  watch              Follow the guest serial boot log
  ssh                Open an SSH session as root on port ${SSH_PORT}
  clean              Stop the TDVM and remove its runtime files

Typical procedure:
  $0 check
  $0 start
  $0 watch
  $0 ssh
EOF
}

check_files() {
    local missing=0
    local path

    for path in \
        "${TD_IMG}" \
        "${VERITY_TREE}" \
        "${ROOT_HASH_FILE}" \
        "${INITRD}" \
        "${KERNEL}"; do
        if [[ ! -f ${path} ]]; then
            echo "Missing: ${path}" >&2
            missing=1
        else
            echo "Found:   ${path}"
        fi
    done

    if [[ -f ${ROOT_HASH_FILE} ]]; then
        local root_hash
        root_hash=$(tr -d '\r\n' < "${ROOT_HASH_FILE}")
        [[ ${root_hash} =~ ^[[:xdigit:]]{64}$ ]] || {
            echo "Invalid root hash in ${ROOT_HASH_FILE}" >&2
            missing=1
        }
    fi

    return "${missing}"
}

build_initramfs() {
    cd "${TACVM_ROOT}"
    sudo ./dm-verity-initramfs/build-initramfs.sh 6.6.0-rc1
}

start_vm() {
    check_files
    cd "${TACVM_ROOT}"
    ./dm_verity.sh
    echo "Watch boot progress with: $0 watch"
    echo "Test SSH with:             $0 ssh"
}

watch_boot() {
    tail -f "${SERIAL_LOG}"
}

ssh_guest() {
    ssh -p "${SSH_PORT}" root@localhost
}

clean_vm() {
    cd "${TACVM_ROOT}"
    ./dm_verity.sh clean
}

case "${1:-}" in
    check)
        check_files
        ;;
    build-initramfs)
        build_initramfs
        ;;
    start)
        start_vm
        ;;
    watch)
        watch_boot
        ;;
    ssh)
        ssh_guest
        ;;
    clean)
        clean_vm
        ;;
    *)
        usage
        exit 1
        ;;
esac