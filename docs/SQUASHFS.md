# SquashFS payload determinism

ODI treats the `payload` section as opaque bytes. One recommended payload format is SquashFS because it is read only, compact, and can be verified by hashing the raw image bytes.

This document defines a *deterministic build profile* for SquashFS payloads so that the same input tree produces identical `payload` bytes.

## Threat model

Non deterministic payloads break ODI’s determinism axiom. The most common causes are:

- varying filesystem timestamps
- varying file order
- varying UID GID ownership
- extended attributes that differ across machines
- tool version differences or non deterministic compressor settings

## Normative requirements for deterministic SquashFS payloads

If you claim an ODI payload is deterministic SquashFS, then the build process MUST satisfy:

1. **Stable order.** The file ordering must be deterministic.
2. **Stable timestamps.** The filesystem creation time and inode timestamps must be fixed.
3. **Stable ownership and permissions.** UID, GID, and modes must be stable.
4. **Stable xattrs policy.** Either xattrs are excluded or included in a deterministic way. ODI recommends excluding xattrs.
5. **Stable toolchain.** The SquashFS tool and its compression settings must be fixed.

## Recommended `mksquashfs` command line

These options are from `mksquashfs(1)` and are commonly available on Linux and FreeBSD ports. For reproducibility:

- `-repro-time TIME` sets filesystem creation time and all inode times to TIME.
- `-sort SORT-FILE` forces deterministic ordering using a sort file.
- `-all-root` makes all files owned by root.
- `-no-xattrs` excludes extended attributes.
- `-no-exports` avoids embedding NFS export data.
- `-nopad` avoids variable padding to 4K boundaries.
- choose a fixed compressor and block size.

Example (use SOURCE_DATE_EPOCH if set, otherwise a chosen constant):

```sh
# Build a deterministic SquashFS payload from ./rootfs into payload.sqfs.
# Requires squashfs-tools (mksquashfs).

TIME="${SOURCE_DATE_EPOCH:-1700000000}"

# Produce a stable, sorted file list.
# Note: adjust find flags for your platform and constraints.
find rootfs -print | LC_ALL=C sort > squashfs.sort

mksquashfs rootfs payload.sqfs \
  -comp xz -b 1M \
  -repro-time "$TIME" \
  -sort squashfs.sort \
  -all-root \
  -no-xattrs \
  -no-exports \
  -nopad
```

### Notes

- `-repro` is a shortcut that sets filesystem creation time to the latest inode timestamp. For strict determinism across rebuilds, prefer `-repro-time`.
- If your build process controls inode times already, you can use `-repro`. Otherwise use `-repro-time` with a fixed timestamp.
- Different `mksquashfs` versions can produce different bytes even with the same flags. Pin the version in your build pipeline.

## ODI guidance

ODI does not mandate SquashFS, but if SquashFS is used then:

- the produced `payload` bytes MUST be hashed into the ODI section table
- the manifest SHOULD describe the payload root inventory, but the payload remains authoritative bytes

