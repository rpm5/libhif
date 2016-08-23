/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 *
 * Copyright (C) 2013-2015 Richard Hughes <richard@hughsie.com>
 *
 * Most of this code was taken from Zif, libzif/zif-transaction.c
 *
 * Licensed under the GNU Lesser General Public License Version 2.1
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or(at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */
/**
 * SECTION:dnf-keyring
 * @short_description: Helper methods for dealing with rpm keyrings.
 * @include: libdnf.h
 * @stability: Unstable
 *
 * These methods make it easier to deal with rpm keyrings.
 */


#include <stdlib.h>
#include <glib.h>

#ifdef	RPM5
#include <rpmio.h>
#include <rpmpgp.h>
#include <rpmtag.h>
#include <pkgio.h>
#include <rpmts.h>
#define _RPMVSF_NODIGESTS       \
  ( RPMVSF_NOSHA1HEADER |       \
    RPMVSF_NOMD5HEADER |        \
    RPMVSF_NOSHA1 |             \
    RPMVSF_NOMD5 )

#define _RPMVSF_NOSIGNATURES    \
  ( RPMVSF_NODSAHEADER |        \
    RPMVSF_NORSAHEADER |        \
    RPMVSF_NODSA |              \
    RPMVSF_NORSA )
#else	/* RPM5 */
#include <rpm/rpmlib.h>
#include <rpm/rpmts.h>
#endif	/* RPM5 */

#include "dnf-types.h"
#include "dnf-keyring.h"
#include "dnf-utils.h"

#ifdef	RPM5
static
pgpArmor pgpParsePkts(const char *armor, uint8_t ** pkt, size_t * pktlen)
{
    pgpArmor ec = PGPARMOR_ERR_NO_BEGIN_PGP;    /* XXX assume failure */
    if (armor && strlen(armor) > 0) {
	rpmiob iob = rpmiobAppend(rpmiobNew(0), armor, 0);
	ec = pgpArmorUnwrap(iob, pkt, pktlen);
	iob = rpmiobFree(iob);
    }
    return ec;
}
#endif	/* RPM5 */

/**
 * dnf_keyring_add_public_key:
 * @keyring: a #rpmKeyring instance.
 * @filename: The public key filename.
 * @error: a #GError or %NULL.
 *
 * Adds a specific public key to the keyring.
 *
 * Returns: %TRUE for success, %FALSE otherwise
 *
 * Since: 0.1.0
 **/
gboolean
dnf_keyring_add_public_key(rpmKeyring keyring,
                           const gchar *filename,
                           GError **error)
{
    gboolean ret = TRUE;
    gsize len;
    pgpArmor armor;
    uint8_t *pkt = NULL;
    g_autofree gchar *data = NULL;

    /* ignore symlinks and directories */
    if (!g_file_test(filename, G_FILE_TEST_IS_REGULAR))
        goto out;
    if (g_file_test(filename, G_FILE_TEST_IS_SYMLINK))
        goto out;

    /* get data */
    ret = g_file_get_contents(filename, &data, &len, error);
    if (!ret)
        goto out;

    /* rip off the ASCII armor and parse it */
    armor = pgpParsePkts(data, &pkt, &len);
    if (armor < 0) {
        ret = FALSE;
        g_set_error(error,
                    DNF_ERROR,
                    DNF_ERROR_GPG_SIGNATURE_INVALID,
                    "failed to parse PKI file %s",
                    filename);
        goto out;
    }

    /* make sure it's something we can add to rpm */
    if (armor != PGPARMOR_PUBKEY) {
        ret = FALSE;
        g_set_error(error,
                    DNF_ERROR,
                    DNF_ERROR_GPG_SIGNATURE_INVALID,
                    "PKI file %s is not a public key",
                    filename);
        goto out;
    }

#ifdef	RPM5
#warning FIXME: dnf_keyring_add_public_key().
#else	/* RPM5 */
    pgpDig dig = NULL;
    rpmPubkey pubkey = NULL;
    gint rc;

    /* test each one */
    pubkey = rpmPubkeyNew(pkt, len);
    if (pubkey == NULL) {
        ret = FALSE;
        g_set_error(error,
                    DNF_ERROR,
                    DNF_ERROR_GPG_SIGNATURE_INVALID,
                    "failed to parse public key for %s",
                    filename);
        goto out;
    }

    /* does the key exist in the keyring */
    dig = rpmPubkeyDig(pubkey);
    rc = rpmKeyringLookup(keyring, dig);
    if (rc == RPMRC_OK) {
        ret = TRUE;
        g_debug("%s is already present", filename);
        goto out;
    }

    /* add to rpmdb automatically, without a prompt */
    rc = rpmKeyringAddKey(keyring, pubkey);
    if (rc == 1) {
        ret = TRUE;
        g_debug("%s is already added", filename);
        goto out;
    } else if (rc < 0) {
        ret = FALSE;
        g_set_error(error,
                    DNF_ERROR,
                    DNF_ERROR_GPG_SIGNATURE_INVALID,
                    "failed to add public key %s to rpmdb",
                    filename);
        goto out;
    }
#endif	/* RPM5 */

    /* success */
    g_debug("added missing public key %s to rpmdb", filename);
    ret = TRUE;
out:
    if (pkt != NULL)
        free(pkt); /* yes, free() */
#ifndef	RPM5
    if (pubkey != NULL)
        rpmPubkeyFree(pubkey);
    if (dig != NULL)
        pgpFreeDig(dig);
#endif	/* RPM5 */
    return ret;
}

/**
 * dnf_keyring_add_public_keys:
 * @keyring: a #rpmKeyring instance.
 * @error: a #GError or %NULL.
 *
 * Adds all installed public keys to the RPM and shared keyring.
 *
 * Returns: %TRUE for success, %FALSE otherwise
 *
 * Since: 0.1.0
 **/
gboolean
dnf_keyring_add_public_keys(rpmKeyring keyring, GError **error)
{
    const gchar *gpg_dir = "/etc/pki/rpm-gpg";
    gboolean ret = TRUE;
    g_autoptr(GDir) dir = NULL;

    /* search all the public key files */
    dir = g_dir_open(gpg_dir, 0, error);
    if (dir == NULL)
        return FALSE;
    do {
        const gchar *filename;
        g_autofree gchar *path_tmp = NULL;
        filename = g_dir_read_name(dir);
        if (filename == NULL)
            break;
        path_tmp = g_build_filename(gpg_dir, filename, NULL);
        ret = dnf_keyring_add_public_key(keyring, path_tmp, error);
    } while (ret);
    return TRUE;
}

/**
 * dnf_keyring_check_untrusted_file:
 */
gboolean
dnf_keyring_check_untrusted_file(rpmKeyring keyring,
                  const gchar *filename,
                  GError **error)
{
    FD_t fd = NULL;
    gboolean ret = FALSE;
    Header hdr = NULL;
    rpmRC rc;
    rpmts ts = NULL;

    /* open the file for reading */
    fd = Fopen(filename, "r.fdio");
    if (fd == NULL) {
        g_set_error(error,
                    DNF_ERROR,
                    DNF_ERROR_FILE_INVALID,
                    "failed to open %s",
                    filename);
        goto out;
    }
    if (Ferror(fd)) {
        g_set_error(error,
                    DNF_ERROR,
                    DNF_ERROR_FILE_INVALID,
                    "failed to open %s: %s",
                    filename,
                    Fstrerror(fd));
        goto out;
    }

    /* we don't want to abort on missing keys */
    ts = rpmtsCreate();
    rpmtsSetVSFlags(ts, _RPMVSF_NOSIGNATURES);

    /* read in the file */
    rc = rpmReadPackageFile(ts, fd, filename, &hdr);
    if (rc != RPMRC_OK) {
        /* we only return SHA1 and MD5 failures, as we're not
         * checking signatures at this stage */
        g_set_error(error,
                    DNF_ERROR,
                    DNF_ERROR_FILE_INVALID,
                    "%s could not be verified",
                    filename);
        goto out;
    }

#ifdef	RPM5

#warning FIXME: dnf_keyring_check_untrusted_file().

#else	/* RPM5 */

    rpmtd td = NULL;
    pgpDig dig = NULL;

    /* convert and upscale */
    headerConvert(hdr, HEADERCONV_RETROFIT_V3);

    /* get RSA key */
    td = rpmtdNew();
    rc = headerGet(hdr,
                   RPMTAG_RSAHEADER,
                   td,
                   HEADERGET_MINMEM);
    if (rc != 1) {
        /* try to read DSA key as a fallback */
        rc = headerGet(hdr,
                       RPMTAG_DSAHEADER,
                       td,
                       HEADERGET_MINMEM);
    }

    /* the package has no signing key */
    if (rc != 1) {
        g_autofree char *package_filename = g_path_get_basename(filename);
        ret = FALSE;
        g_set_error(error,
                    DNF_ERROR,
                    DNF_ERROR_GPG_SIGNATURE_INVALID,
                    "package not signed: %s", package_filename);
        goto out;
    }

    /* make it into a digest */
    dig = pgpNewDig();
    rc = pgpPrtPkts(td->data, td->count, dig, 0);
    if (rc != 0) {
        g_set_error(error,
                    DNF_ERROR,
                    DNF_ERROR_FILE_INVALID,
                    "failed to parse digest header for %s",
                    filename);
        goto out;
    }

    /* does the key exist in the keyring */
    rc = rpmKeyringLookup(keyring, dig);
    if (rc != RPMRC_OK) {
        g_set_error(error,
                    DNF_ERROR,
                    DNF_ERROR_GPG_SIGNATURE_INVALID,
                    "failed to lookup digest in keyring for %s",
                    filename);
        goto out;
    }
#endif	/* RPM5 */

    /* the package is signed by a key we trust */
    g_debug("%s has been verified as trusted", filename);
    ret = TRUE;
out:
#ifndef	RPM5
    if (dig != NULL)
        pgpFreeDig(dig);
    if (td != NULL) {
        rpmtdFreeData(td);
        rpmtdFree(td);
    }
#endif	/* RPM5 */
    if (ts != NULL)
        rpmtsFree(ts);
    if (hdr != NULL)
        headerFree(hdr);
    if (fd != NULL)
        Fclose(fd);
    return ret;
}
