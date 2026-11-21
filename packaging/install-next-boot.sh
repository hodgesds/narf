#!/usr/bin/env bash
# Install a native EFI image for the NUC's existing "NARF native EFI" GRUB entry.
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
boot_dir=/boot
entry='NARF native EFI'
efi_path=/EFI/NARF-NATIVE/narf.efi
dry_run=false

usage() {
    echo "Usage: $0 [--dry-run] [--boot-directory DIR] [BOOTX64.EFI]"
}
die() { echo "$0: $*" >&2; exit 1; }

while (( $# )); do
    case $1 in
        --dry-run) dry_run=true; shift ;;
        --boot-directory) [[ $# -ge 2 ]] || die 'missing boot directory'; boot_dir=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        --) shift; break ;;
        -*) usage >&2; exit 2 ;;
        *) break ;;
    esac
done
(( $# <= 1 )) || { usage >&2; exit 2; }
image=${1:-"$script_dir/../target/native-uefi-x86_64/esp/EFI/BOOT/BOOTX64.EFI"}
grub_cfg=$boot_dir/grub/grub.cfg
grub_env=$boot_dir/grub/grubenv
dest=$boot_dir$efi_path

# This layout keeps the GRUB environment and the chainloaded image on one ESP.
[[ -f $grub_env && -f $grub_cfg ]] || die "missing GRUB environment or configuration in $boot_dir/grub"
boot_fs=$(findmnt -nro FSTYPE --mountpoint "$boot_dir")
case "$boot_fs" in
    vfat)
        [[ $(grub-probe --target=fs "$grub_env") == fat ]] || die 'GRUB does not see its environment on FAT'
        abstraction=$(grub-probe --target=abstraction "$grub_env")
        [[ -z $abstraction ]] || die "GRUB cannot clear next_entry on this abstraction: $abstraction"
        ;;
    fat32)
        # NARF names the driver fat32. grub-probe cannot map its sysfs block
        # topology, but GRUB can read and compare the files on the plain ESP.
        esp_device=$(findmnt -nro SOURCE --mountpoint "$boot_dir")
        [[ $esp_device =~ ^(/dev/nvme[0-9]+n[0-9]+)p([1-9][0-9]*)$ ]] ||
            die 'cannot identify the physical NVMe disk and ESP partition'
        esp_disk=${BASH_REMATCH[1]}
        grub_partition="(loop0,gpt${BASH_REMATCH[2]})"
        [[ -b $esp_disk && -b $esp_device && $(blkid -p -s TYPE -o value "$esp_device") == vfat ]] ||
            die "$boot_dir must be backed by a FAT block device"
        grub-fstest "$esp_disk" cmp "$grub_partition/grub/grub.cfg" "$grub_cfg" ||
            die 'GRUB cannot read the installed configuration directly from the ESP'
        grub-fstest "$esp_disk" cmp "$grub_partition/grub/grubenv" "$grub_env" ||
            die 'GRUB cannot read the installed environment directly from the ESP'
        ;;
    *) die "$boot_dir must be the mounted FAT EFI System Partition" ;;
esac
awk -v title="menuentry '$entry' " -v path="$efi_path" '
    /^menuentry / { selected = index($0, title) == 1 }
    /^}/ { selected = 0 }
    selected && $1 == "chainloader" {
        file = $2
        sub(/^\([^)]*\)/, "", file)
        if (file == path) found = 1
    }
    $1 == "set" && $2 == "default=\"${next_entry}\"" { uses_next = 1 }
    uses_next && $1 == "set" && $2 == "next_entry=" { clears_next = 1 }
    clears_next && $1 == "save_env" && $NF == "next_entry" { saves_next = 1 }
    END { exit !(found && saves_next) }
' "$grub_cfg" || die "$grub_cfg must chainload $efi_path from '$entry' and consume next_entry"

grub-editenv "$grub_env" list >/dev/null
if $dry_run; then
    python3 "$script_dir/native-efi.py" "$image" >/dev/null
    printf 'Would install %s at %s and select "%s" for the next GRUB boot.\n' "$image" "$dest" "$entry"
    exit 0
fi

# NARF's mounted FAT32 driver cannot replace an existing directory entry or
# reliably write a large file. Use mtools exclusively while the ESP is offline.
install_narf_esp() (
    exec 9<"$esp_device"
    flock --exclusive 9
    local work options live staged backup
    work=$(mktemp -d)
    options=$(findmnt -nro OPTIONS --mountpoint "$boot_dir")
    live="::$efi_path"
    staged="::${efi_path%/*}/NARFNEW.EFI"
    backup="::${efi_path%/*}/NARFBAK.EFI"
    local detached=false offline=false moved=false env_started=false committed=false
    exists() { mdir -i "$esp_device" "$1" >/dev/null 2>&1; }
    cleanup() {
        local rc=$?
        trap - EXIT
        set +e
        if $offline; then
            if ! $committed; then
                if $env_started; then
                    mcopy -o -i "$esp_device" "$work/original" ::/grub/grubenv || rc=1
                fi
                if $moved; then
                    if exists "$live"; then mdel -i "$esp_device" "$live" || rc=1; fi
                    mren -i "$esp_device" "$backup" "$live" || rc=1
                fi
            fi
            if exists "$staged"; then mdel -i "$esp_device" "$staged" || rc=1; fi
            sync || rc=1
        fi
        if $detached; then
            mount -t fat32 -o "$options" "$esp_device" "$boot_dir" || rc=1
        fi
        rm -f -- "$work/original" "$work/next"
        rmdir -- "$work"
        exit "$rc"
    }
    trap cleanup EXIT
    python3 "$script_dir/native-efi.py" "$image" >/dev/null
    cat "$grub_env" >"$work/original"
    cp -- "$work/original" "$work/next"
    grub-editenv "$work/next" set "next_entry=$entry"
    grub-editenv "$work/next" list | grep -Fx "next_entry=$entry" >/dev/null
    [[ $(findmnt -rn -S "$esp_device" -o TARGET) == "$boot_dir" ]] ||
        die 'the ESP must have a single mount before updating it offline'
    sync -f "$boot_dir"
    umount -- "$boot_dir"
    detached=true
    if findmnt -rn -S "$esp_device" >/dev/null; then
        die 'the ESP still has a mount after unmounting the boot directory'
    fi
    offline=true
    # Resume an interrupted rename. Both scratch names are reserved here.
    if exists "$backup"; then
        if exists "$live"; then mdel -i "$esp_device" "$live"; fi
        mren -i "$esp_device" "$backup" "$live"
    fi
    if ! grub-fstest "$esp_disk" cmp "$grub_partition$efi_path" "$image" >/dev/null 2>&1; then
        mcopy -o -i "$esp_device" "$image" "$staged"
        grub-fstest "$esp_device" cmp "${staged#::}" "$image"
        if exists "$live"; then
            mren -i "$esp_device" "$live" "$backup"
            moved=true
        fi
        mren -i "$esp_device" "$staged" "$live"
    fi
    grub-fstest "$esp_disk" cmp "$grub_partition$efi_path" "$image"
    env_started=true
    mcopy -o -i "$esp_device" "$work/next" ::/grub/grubenv
    sync
    grub-fstest "$esp_disk" cmp "$grub_partition/grub/grubenv" "$work/next"
    committed=true
    if $moved; then mdel -i "$esp_device" "$backup"; fi
)

if [[ $boot_fs == fat32 ]]; then
    install_narf_esp
    printf 'Installed %s. Next GRUB boot: %s.\n' "$dest" "$entry"
    exit 0
fi

exec 9<"$boot_dir"
flock --exclusive 9
if ! cmp -s -- "$image" "$dest"; then
    mkdir -p -- "$(dirname -- "$dest")"
    staged=$(mktemp -- "$dest.XXXXXXXX")
    trap 'rm -f -- "$staged"' EXIT
    install -m 0644 -- "$image" "$staged"
    cmp -- "$image" "$staged"
    python3 "$script_dir/native-efi.py" "$staged" >/dev/null
    sync -f "$staged"
    mv -fT -- "$staged" "$dest"
    trap - EXIT
else
    python3 "$script_dir/native-efi.py" "$dest" >/dev/null
fi
sync -f "$boot_dir"

# GRUB consumes next_entry before chainloading. Its regular default is separate.
grub-editenv "$grub_env" set "next_entry=$entry"
sync -f "$grub_env"
grub-editenv "$grub_env" list | grep -Fx "next_entry=$entry" >/dev/null ||
    die 'could not verify the next GRUB boot selection'
printf 'Installed %s. Next GRUB boot: %s.\n' "$dest" "$entry"
