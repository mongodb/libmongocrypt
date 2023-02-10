# This script is used to tweak the upstream libmongocrypt.spec file such that
# the rpm build will build from a copy of the source tree instead of by
# unpacking an archive of the sources

# Drop the gcc-13 patch.
/Patch.*gcc-13/ { next }

# Drop the source. We're bringing our own
/Source0/ { next }

/%package devel/ {
    # Insert a dep on 'libdfp-devel'
    print
    print "BuildRequires: libdfp-devel"
    print "Requires: libdfp"
    next
}

/-DMONGOCRYPT_MONGOC_DIR:STRING=USE-SYSTEM/ {
    print
    print "   -DMONGOCRYPT_DFP_DIR=USE-SYSTEM \\"
    next
}

# Replace the autosetup with one that copies the source tree into place
/%autosetup/ {
    print "cp -rf %{_sourcedir}/. %{_builddir}/\n" \
          "%autopatch 0 -p1"
    next
}

# Print every other line as-is
{ print }
