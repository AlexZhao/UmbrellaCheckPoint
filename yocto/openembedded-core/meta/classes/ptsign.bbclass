#
# Copyright OpenEmbedded Contributors
#
# SPDX-License-Identifier: MIT
#
# Class for processing ELF files in PKGD after do_package
# This class adds a function to process all ELF files in PKGD directory,
# excluding symlinks, by calling an external command.
#

# External command to process ELF files
# This variable should be set to the command that will be called for each ELF file
# The ELF file path will be appended to this command
PT_ELF_SIGN_CMD ?= "${TARGET_ARCH}${TARGET_VENDOR}-${TARGET_OS}-elfsign"

# If set to '1', the processor command will be called
ENABLE_PT_SIGN ?= "0"

# Signature Private Key
PT_SIGN_KEY ?= "pt-sign.key"

# Key path
PT_SIGN_KEY_PATH = "${TOPDIR}/conf/${PT_SIGN_KEY}"

python do_ptsign() {
    import os
    import subprocess

    # Check if processor is enabled and command is set
    enabled = d.getVar('ENABLE_PT_SIGN') or "0"
    if enabled != "1":
        bb.debug(1, "ELF processor is not enabled")
        return

    cmd = d.getVar('PT_ELF_SIGN_CMD')
    if not cmd:
        bb.warn("PT_ELF_SIGN_CMD is not set, skipping ELF sign")
        return

    pkgd = d.getVar('PKGD')
    if not pkgd or not os.path.exists(pkgd):
        bb.debug(1, "PKGD directory does not exist, skipping ELF sign")
        return

    # Count of processed ELF files
    processed_count = 0
    skipped_count = 0

    # Walk through PKGD directory to find ELF files
    bb.note("Sign ELF files in %s" % pkgd)
    for root, dirs, files in os.walk(pkgd):
        for fname in files:
            filepath = os.path.join(root, fname)

            # Skip symlinks
            if os.path.islink(filepath):
                skipped_count += 1
                continue

            # Skip directories
            if not os.path.isfile(filepath):
                skipped_count += 1
                continue

            # Check if file is ELF
            try:
                # Read first 4 bytes to check ELF magic number
                with open(filepath, 'rb') as f:
                    magic = f.read(4)

                if magic != b'\x7fELF':
                    skipped_count += 1
                    continue

                # Process the ELF file with external command
                bb.debug(2, "Sign ELF file: %s" % filepath)
                full_cmd = "%s --input %s --private-key %s" % (cmd, filepath, d.getVar('PT_SIGN_KEY_PATH'))
                try:
                    subprocess.check_call(full_cmd, shell=True)
                    processed_count += 1
                    bb.debug(2, "Successfully Signed: %s" % filepath)
                except subprocess.CalledProcessError as e:
                    if e.returncode == 1:
                        bb.warn("Failed to sign ELF file %s: %s" % (filepath, str(e)))
                    elif e.returncode == 2:
                        bb.debug(4, "Not a final ELF file for ptsign %s: %s" % (filepath, str(e)))
                except Exception as e:
                    bb.warn("Error sign ELF file %s: %s" % (filepath, str(e)))

            except (IOError, OSError) as e:
                bb.debug(3, "Cannot read file %s: %s" % (filepath, str(e)))
                skipped_count += 1

    bb.note("ELF Sign complete: processed %d files, skipped %d files" % (processed_count, skipped_count))
}

addtask ptsign after do_package before do_packagedata
#do_cve_check[depends] = "${CVE_CHECK_DB_FETCHER}:do_unpack"
do_packagedata[postfuncs] += "do_ptsign"
