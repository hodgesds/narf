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
[[ $(findmnt -nro FSTYPE --mountpoint "$boot_dir") == vfat ]] ||
    die "$boot_dir must be the mounted FAT EFI System Partition"
[[ -f $grub_env && -f $grub_cfg ]] || die "missing GRUB environment or configuration in $boot_dir/grub"
[[ $(grub-probe --target=fs "$grub_env") == fat ]] || die 'GRUB does not see its environment on FAT'
abstraction=$(grub-probe --target=abstraction "$grub_env")
[[ -z $abstraction ]] || die "GRUB must be able to clear next_entry on a plain partition (found $abstraction)"
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
