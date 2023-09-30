/* elfsign.c -- Signing the compiled ELF with private key.
   Author: Zhao Zhe (Alex), zhe.alex.zhao@gmail.com

   Copyright (C) 1991-2023 Free Software Foundation, Inc.

   This file is part of GNU Binutils.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.  */
#include "sysdep.h"
#include "bfd.h"
#include "libiberty.h"
#include "elfcomm.h"
#include "bucomm.h"
#include "fnmatch.h"
#include "budbg.h"
#include "elf-bfd.h"
#include "getopt.h"
#include "safe-ctype.h"
#include "filenames.h"

#include "elf/internal.h"

/* OpenSSL relevant SHA and RSA sign */
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/engine.h>
#include <openssl/err.h>

extern char *program_name;

static asymbol **isympp = NULL;	/* Input symbols.  */
static asymbol **osympp = NULL;	/* Output symbols that survive stripping.  */

enum command_line_switch {
    OPTION_PRIVATE_KEY = 160,
    OPTION_INPUT,
    OPTION_OUTPUT,
};

typedef enum {
    NO_SIGNATURE = 0,
    SHA256_RSA2048,
    SHA256_RSA4096,
    SHA512_RSA2048,
    SHA512_RSA4096
} signature_sign_combination_e;

typedef struct signature_item {
    signature_sign_combination_e sign_type;
    char signature[512];
    char cert_file[];
} signature_item_t;

typedef struct signature_section {
    int sig_cnt;
    signature_item_t sigs[];
} signature_section_t;

static struct option options[] = {
    {"input",	required_argument, 0, OPTION_INPUT},
    {"output", required_argument, 0, OPTION_OUTPUT},
    {"private_key", required_argument, 0, OPTION_PRIVATE_KEY},
    {"version", no_argument, 0, 'v'},
    {"help", no_argument, 0, 'h'},
    {0, no_argument, 0, 0}
};

/*
 * Calculate PT_SIGN section of ELF binary
 * Copy data from OpenSSL allocated data to xmalloc data
 */
static int calculate_sign_section(bfd *obfd, char *signature, size_t len, const char *priv_key)
{
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    Elf_Internal_Ehdr *ehdr = elf_elfheader(obfd);
    unsigned int digest_len = 0;
    FILE *key = NULL;
    int ret = 1;
    void *tmp = NULL;
    void *digest = NULL;

    if (ehdr == NULL) 
        goto err;

    key = fopen(priv_key, "r");
    if (key == NULL)
        goto err;

    pkey = PEM_read_PrivateKey(key, NULL, NULL, NULL);
    if (pkey == NULL)
        goto err_close_key;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) 
        goto err_close_key;

    if (EVP_DigestInit(ctx, EVP_sha256()) == 0)
        goto err_free_ctx;

    if (EVP_DigestUpdate(ctx, ehdr, sizeof(Elf_Internal_Ehdr)) == 0)
        goto err_free_ctx;

    digest = OPENSSL_malloc(256);
    if (digest == NULL)
        goto err_free_ctx;

    if (EVP_DigestFinal(ctx, digest, &digest_len) == 0)
        goto err_free_ctx;

    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!pctx)
        goto err_free_ctx;

    size_t sig_len = 0;
    EVP_PKEY_sign_init(pctx);

    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING);

    EVP_PKEY_CTX_set_signature_md(pctx, EVP_sha256());
    
    EVP_PKEY_sign(pctx, NULL, &sig_len, digest, digest_len);

    tmp = OPENSSL_malloc(sig_len);
    if (tmp == NULL)
        goto err_free_ctx;

    EVP_PKEY_sign(pctx, tmp, &sig_len, digest, digest_len);

    if (len != sig_len)
        goto err_free_ctx;

    memcpy(signature, tmp, sig_len);

    ret = 0;

err_free_ctx:
    if (tmp)
        OPENSSL_free(tmp);

    if (pctx)
        EVP_PKEY_CTX_free(pctx);

    if (digest)
        OPENSSL_free(digest);

    if (ctx)
        EVP_MD_CTX_free(ctx);

    if (pkey)
        OPENSSL_free(pkey);

err_close_key:
    if (key)
        fclose(key);

err:
    return ret;
}

/*
 *  Create a section in OBFD with the same
 *  name and attributes as ISECTION in IBFD.
 *
 */
static void setup_section(bfd *ibfd, sec_ptr isection, void *obfdarg)
{
    bfd *obfd = (bfd *) obfdarg;
    sec_ptr osection;
    bfd_size_type size;
    bfd_vma vma;
    bfd_vma lma;
    flagword flags;
    const char *err = NULL;
    const char * name;
    unsigned int alignment;

    /* Get the, possibly new, name of the output section.  */
    name = bfd_section_name (isection);
    flags = bfd_section_flags (isection);
    if (bfd_get_flavour (ibfd) != bfd_get_flavour (obfd)) {
        flags &= bfd_applicable_section_flags (ibfd);
        flags &= bfd_applicable_section_flags (obfd);
    }

    if (!bfd_convert_section_setup (ibfd, isection, obfd, &name, &size)) {
        osection = NULL;
        err = _("failed to create output section");
        goto loser;
    }

    osection = bfd_make_section_anyway_with_flags (obfd, name, flags);

    if (osection == NULL) {
        err = _("failed to create output section");
        goto loser;
    }

    if (!bfd_set_section_size (osection, size))
        err = _("failed to set size");

    vma = bfd_section_vma (isection);

    if (!bfd_set_section_vma (osection, vma))
        err = _("failed to set vma");

    lma = isection->lma;

    osection->lma = lma;

    alignment = bfd_section_alignment (isection);

    /* FIXME: This is probably not enough.  If we change the LMA we
       may have to recompute the header for the file as well.  */
    if (!bfd_set_section_alignment (osection, alignment))
        err = _("failed to set alignment");

    /* Copy merge entity size.  */
    osection->entsize = isection->entsize;

    /* Copy compress status.  */
    osection->compress_status = isection->compress_status;

    /* This used to be mangle_section; we do here to avoid using
       bfd_get_section_by_name since some formats allow multiple
       sections with the same name.  */
    isection->output_section = osection;
    isection->output_offset = 0;

    /* Allow the BFD backend to copy any private data it understands
       from the input section to the output section.  */
    if (!bfd_copy_private_section_data (ibfd, isection, obfd, osection))
        err = _("failed to copy private data");

    if (!err)
        return;

loser:
    bfd_nonfatal_message (NULL, obfd, osection, err);
}


static void
copy_relocations_in_section (bfd *ibfd, sec_ptr isection, void *obfdarg)
{
    bfd *obfd = (bfd *) obfdarg;
    long relsize;
    arelent **relpp;
    long relcount;
    sec_ptr osection;

    osection = isection->output_section;

    relsize = bfd_get_reloc_upper_bound (ibfd, isection);

    if (relsize < 0) {
        /* Do not complain if the target does not support relocations.  */
        if (relsize == -1 && bfd_get_error () == bfd_error_invalid_operation)
            relsize = 0;
        else {
            bfd_nonfatal_message (NULL, ibfd, isection, NULL);
            return;
        }
    }

    if (relsize == 0)
        bfd_set_reloc (obfd, osection, NULL, 0);
    else {
        if (isection->orelocation != NULL) {
            /* Some other function has already set up the output relocs
               for us, so scan those instead of the default relocs.  */
            relcount = isection->reloc_count;
            relpp = isection->orelocation;
        } else {
            relpp = bfd_xalloc (obfd, relsize);
            relcount = bfd_canonicalize_reloc (ibfd, isection, relpp, isympp);
            if (relcount < 0) {
                bfd_nonfatal_message (NULL, ibfd, isection,
                                      _("relocation count is negative"));
                return;
            }
        }

        bfd_set_reloc (obfd, osection, relcount == 0 ? NULL : relpp, relcount);
    }
}


static void
copy_section (bfd *ibfd, sec_ptr isection, void *obfdarg)
{
    bfd *obfd = (bfd *) obfdarg;
    sec_ptr osection;
    bfd_size_type size;

    osection = isection->output_section;
    /* The output SHF_COMPRESSED section size is different from input if
       ELF classes of input and output aren't the same.  We can't use
       the output section size since --interleave will shrink the output
       section.   Size will be updated if the section is converted.   */
    size = bfd_section_size (isection);

    if (bfd_section_flags (isection) & SEC_HAS_CONTENTS
        && bfd_section_flags (osection) & SEC_HAS_CONTENTS) {
        bfd_byte *memhunk = NULL;

        if (!bfd_get_full_section_contents (ibfd, isection, &memhunk)
            || !bfd_convert_section_contents (ibfd, isection, obfd,
                                              &memhunk, &size)) {
            bfd_set_section_size (osection, 0);
            bfd_nonfatal_message (NULL, ibfd, isection, NULL);
            free (memhunk);
            return;
        }

        if (!bfd_set_section_contents (obfd, osection, memhunk, 0, size)) {
            bfd_nonfatal_message (NULL, obfd, osection, NULL);
            free (memhunk);
            return;
        }
        free (memhunk);
    }
}

/*
 *  Add signature section to elf binary
 *  Update program header to have PT_SIGN point to
 *  New section .signature
 *
 *  bfd_record_phdr (bfd *abfd, )
 *
 *  with modified BFD
 *
 */
static struct bfd_section* add_sign_section(bfd *obfd, size_t sign_len)
{
    struct bfd_section **sign_section = NULL;
    struct bfd_section *section = NULL;
    flagword flags;
    flags = SEC_HAS_CONTENTS | SEC_READONLY | SEC_DATA;

    section = bfd_make_section_with_flags (obfd, ".signature", flags | SEC_LINKER_CREATED);
    if (section == NULL) {
        bfd_nonfatal_message (NULL, obfd, NULL, _("can't create section .signature"));
        return NULL;
    }

    if (!bfd_set_section_size (section, sign_len)) {
        bfd_nonfatal_message (NULL, obfd, section, NULL);
        return NULL;
    }

    sign_section = xmalloc(sizeof(struct bfd_section *));
    *sign_section = section;

    bfd_record_phdr (obfd, PT_SIGN, 0, 0, 0, 0, 0, 0, 1, sign_section);

    return *sign_section;
}


/* Once each of the sections is copied, we may still need to do some
   finalization work for private section headers.  Do that here.  */

static bool setup_bfd_headers (bfd *ibfd, bfd *obfd)
{
    /* Allow the BFD backend to copy any private data it understands
       from the input section to the output section.  */
    if (! bfd_copy_private_header_data (ibfd, obfd)) {
        bfd_nonfatal_message (NULL, ibfd, NULL,
                              _("error in private header data"));
        return false;
    }

    /* All went well.  */
    return true;
}

/*
 *  Sign ELF file
 */
static int sign_file(const char *input_elf, const char *private_key, const char *output_elf)
{
    struct stat statbuf;
    const char* input_target = NULL;
    const char* output_target = NULL;
    char *signature = NULL;
    size_t sign_len = 256;
    bfd *ibfd = NULL;
    bfd *obfd = NULL;
    struct bfd_section *sign_section = NULL;
    enum bfd_architecture iarch;
    unsigned int imach;
    bfd_vma start;
    char **obj_matching;
    long symcount;
    long symsize;

    ibfd = bfd_openr (input_elf, input_target);
    if (ibfd == NULL || bfd_stat (ibfd, &statbuf) != 0) {
        bfd_nonfatal_message (input_elf, NULL, NULL, NULL);
        if (ibfd != NULL)
            bfd_close (ibfd);
        return 1;
    }

    if (bfd_check_format_matches (ibfd, bfd_object, &obj_matching)) {

        /* Only support from ibfd to obfd same compiling target */
        output_target = bfd_get_target (ibfd);
        obfd = bfd_openw (output_elf, output_target);
        if (obfd == NULL) {
            bfd_nonfatal_message (output_elf, NULL, NULL, NULL);
            bfd_close (ibfd);
            return 1;
        }

        if (ibfd->xvec->byteorder != obfd->xvec->byteorder
            && ibfd->xvec->byteorder != BFD_ENDIAN_UNKNOWN
            && obfd->xvec->byteorder != BFD_ENDIAN_UNKNOWN) {
            non_fatal (_("unable to change endianness of '%s'"),
                       bfd_get_archive_filename (ibfd));
            return 1;
        }

        if (!bfd_set_format (obfd, bfd_get_format (ibfd))) {
            printf("%s:%d %d\n", __func__, __LINE__, bfd_get_format(ibfd));
            bfd_nonfatal_message (NULL, obfd, NULL, NULL);
            return 1;
        }

        if (ibfd->sections == NULL) {
            non_fatal (_("error: the input file '%s' has no sections"),
                       bfd_get_archive_filename (ibfd));
            return 1;
        }

        start = bfd_get_start_address (ibfd);
        /* Neither the start address nor the flags
           need to be set for a core file.  */
        if (bfd_get_format (obfd) != bfd_core) {
            flagword flags;

            flags = bfd_get_file_flags (ibfd);
            flags &= bfd_applicable_file_flags (obfd);

            if (!bfd_set_start_address (obfd, start)
                || !bfd_set_file_flags (obfd, flags)) {
                bfd_nonfatal_message (NULL, ibfd, NULL, NULL);
                return 1;
            }
        }

        /* Copy architecture of input file to output file.  */
        iarch = bfd_get_arch (ibfd);
        imach = bfd_get_mach (ibfd);

        if (iarch == bfd_arch_unknown
            && bfd_get_flavour (ibfd) != bfd_target_elf_flavour
            && bfd_get_flavour (obfd) == bfd_target_elf_flavour) {
            const struct elf_backend_data *bed = get_elf_backend_data (obfd);
            iarch = bed->arch;
            imach = 0;
        }

        if (!bfd_set_arch_mach (obfd, iarch, imach)
            && (ibfd->target_defaulted
                || bfd_get_arch (ibfd) != bfd_get_arch (obfd))) {
            if (bfd_get_arch (ibfd) == bfd_arch_unknown)
                non_fatal (_("Unable to recognise the format of the input file `%s'"),
                           bfd_get_archive_filename (ibfd));
            else
                non_fatal (_("Output file cannot represent architecture `%s'"),
                           bfd_printable_arch_mach (bfd_get_arch (ibfd),
                                                    bfd_get_mach (ibfd)));
            return 1;
        }

        if (!bfd_set_format (obfd, bfd_get_format (ibfd))) {
            bfd_nonfatal_message (NULL, ibfd, NULL, NULL);
            return 1;
        }

        isympp = NULL;
        osympp = NULL;

        symsize = bfd_get_symtab_upper_bound (ibfd);
        if (symsize < 0) {
            bfd_nonfatal_message (NULL, ibfd, NULL, NULL);
            return 1;
        }

        osympp = isympp = (asymbol **) xmalloc (symsize);
        symcount = bfd_canonicalize_symtab (ibfd, isympp);
        if (symcount < 0) {
            bfd_nonfatal_message (NULL, ibfd, NULL, NULL);
            return 1;
        }

        if (symcount == 0) {
            free (isympp);
            osympp = isympp = NULL;
        }

        /* BFD mandates that all output sections be created and sizes set before
           any output is done.  Thus, we traverse all sections multiple times.  */
        bfd_map_over_sections (ibfd, setup_section, obfd);

        sign_section = add_sign_section (obfd, sign_len);

        if (setup_bfd_headers (ibfd, obfd) != true)
            return 1;

        /* Section Hdr and Program Hdr Configuration Ready */

        bfd_set_symtab (obfd, osympp, symcount);

        /* This has to happen before section positions are set.  */
        bfd_map_over_sections (ibfd, copy_relocations_in_section, obfd);

        /* This has to happen after the symbol table has been set.  */
        bfd_map_over_sections (ibfd, copy_section, obfd);

        /* Calculate SHA256 and Sign with RSA2048 */
        signature = malloc(sign_len);
        memset(signature, 0x00, sign_len);

        if (calculate_sign_section(obfd, signature, sign_len, private_key))
            return 1;

        /* Setup the contents of obfd */
        if (! bfd_set_section_contents (obfd, sign_section, (const void *)signature, 0, sign_len)) {
            bfd_nonfatal_message (NULL, obfd, sign_section, NULL);
            return 1;
        }

        /* Allow the BFD backend to copy any private data it understands
           from the input BFD to the output BFD.  This is done last to
           permit the routine to look at the filtered symbol table, which is
           important for the ECOFF code at least.  */
        if (! bfd_copy_private_bfd_data (ibfd, obfd)) {
            bfd_nonfatal_message (NULL, obfd, NULL,
                                  _("error copying private BFD data"));
            return 1;
        }

        if (!bfd_close (obfd)) {
            bfd_nonfatal_message (output_elf, NULL, NULL, NULL);
        }

        if (!bfd_close (ibfd)) {
            bfd_nonfatal_message (input_elf, NULL, NULL, NULL);
        }
        return 0;
    } else {
        bfd_nonfatal_message (input_elf, NULL, NULL, NULL);
        if (ibfd != NULL)
            bfd_close (ibfd);
        return 1;
    }
}

ATTRIBUTE_NORETURN static void usage (FILE *stream, int exit_status)
{
    fprintf(stream, _(" Usage: %s <option(s)> elffile(s)\n"), program_name);
    fprintf(stream, _(" Update the ELF header of ELF files\n"));
    fprintf(stream, _(" The options are:\n"));
    fprintf(stream, _("\
  --input elf input file need to sign\n\
  --output elf output file after signed\n\
  --private_key private key file used to sign the ELF\n"));
    fprintf(stream, _("\
  -h --help                   Display this information\n\
  -v --version                Display the version number of %s\n"), program_name);

    exit (exit_status);
}

int main(int argc, char *argv[])
{
    int c, status;
    char *input_elf = NULL;
    char *output_elf = NULL;
    char *private_key = NULL;

    /* Set elfsign name */
    program_name = argv[0];
    expandargv (&argc, &argv);

    while ((c = getopt_long (argc, argv, "hv",
                             options, (int *) 0)) != EOF) {
        switch (c) {
        case OPTION_PRIVATE_KEY:
            private_key = optarg;
            break;
        case OPTION_INPUT:
            input_elf = optarg;
            break;
        case OPTION_OUTPUT:
            output_elf = optarg;
            break;
        case 'h':
            usage(stdout, 0);
        case 'v':
            print_version(program_name);
            break;
        default:
            usage(stderr, 1);
        }
    }

    status = sign_file(input_elf, private_key, output_elf);
    if (status)
        printf("Failed sign ELF %s with private key %s\n", input_elf, private_key);
    else
        printf("Success sign ELF %s with private key %s\n", input_elf, private_key);

    return status;
}
