/* Copyright (c) 2011, SmartFile <btimby@smartfile.com>
 All rights reserved.

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are met:
     * Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.
     * Neither the name of the organization nor the
       names of its contributors may be used to endorse or promote products
       derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE LIABLE FOR ANY
 DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

%module _libarchive

%{
#include <archive.h>
#include <archive_entry.h>
%}

%include "typemaps.i"

%typemap(in) time_t
{
    if (PyLong_Check($input))
        $1 = (time_t) PyLong_AsLong($input);
    else if (PyInt_Check($input))
        $1 = (time_t) PyInt_AsLong($input);
    else if (PyFloat_Check($input))
        $1 = (time_t) PyFloat_AsDouble($input);
    else {
        PyErr_SetString(PyExc_TypeError,"Expected a large number");
        return NULL;
    }
}

%typemap(out) time_t
{
    $result = PyLong_FromLong((long)$1);
}

%typemap(in) int64_t
{
    if (PyLong_Check($input))
        $1 = (int64_t) PyLong_AsLong($input);
    else if (PyInt_Check($input))
        $1 = (int64_t) PyInt_AsLong($input);
    else if (PyFloat_Check($input))
        $1 = (int64_t) PyFloat_AsDouble($input);
    else {
        PyErr_SetString(PyExc_TypeError,"Expected a large number");
        return NULL;
    }
}

%typemap(out) int64_t
{
    $result = PyLong_FromLong((long)$1);
}

typedef unsigned short   mode_t;


/* CONFIGURATION */

#include <sys/types.h>
#include <stddef.h>  /* for wchar_t */
#include <time.h>

#if defined(_WIN32) && !defined(__CYGWIN__)
#include <windows.h>
#endif

/* Get appropriate definitions of standard POSIX-style types. */
/* These should match the types used in 'struct stat' */
#if defined(_WIN32) && !defined(__CYGWIN__)
#define	__LA_INT64_T	__int64
# if defined(__BORLANDC__)
#  define	__LA_UID_T	uid_t  /* Remove in libarchive 3.2 */
#  define	__LA_GID_T	gid_t  /* Remove in libarchive 3.2 */
#  define	__LA_DEV_T	dev_t
#  define	__LA_MODE_T	mode_t
# else
#  define	__LA_UID_T	short  /* Remove in libarchive 3.2 */
#  define	__LA_GID_T	short  /* Remove in libarchive 3.2 */
#  define	__LA_DEV_T	unsigned int
#  define	__LA_MODE_T	unsigned short
# endif
#else
#include <unistd.h>
# if defined(_SCO_DS)
#  define	__LA_INT64_T	long long
# else
#  define	__LA_INT64_T	int64_t
# endif
# define	__LA_UID_T	uid_t /* Remove in libarchive 3.2 */
# define	__LA_GID_T	gid_t /* Remove in libarchive 3.2 */
# define	__LA_DEV_T	dev_t
# define	__LA_MODE_T	mode_t
#endif

/*
 * Remove this for libarchive 3.2, since ino_t is no longer used.
 */
#define	__LA_INO_T	ino_t


/*
 * On Windows, define LIBARCHIVE_STATIC if you're building or using a
 * .lib.  The default here assumes you're building a DLL.  Only
 * libarchive source should ever define __LIBARCHIVE_BUILD.
 */
#if ((defined __WIN32__) || (defined _WIN32) || defined(__CYGWIN__)) && (!defined LIBARCHIVE_STATIC)
# ifdef __LIBARCHIVE_BUILD
#  ifdef __GNUC__
#   define extern	__attribute__((dllexport)) extern
#  else
#   define extern	__declspec(dllexport)
#  endif
# else
#  ifdef __GNUC__
#   define extern
#  else
#   define extern	__declspec(dllimport)
#  endif
# endif
#else
/* Static libraries on all platforms and shared libraries on non-Windows. */
# define extern
#endif

/* STRUCTURES */
struct archive;
struct archive_entry;

/* ARCHIVE READING */
extern struct archive	*archive_read_new(void);
extern int		 archive_read_free(struct archive *);

/* opening */
extern int archive_read_open_filename(struct archive *,
		     const char *_filename, size_t _block_size);
extern int archive_read_open_memory(struct archive *,
		     const void * buff, size_t size);
extern int archive_read_open_memory2(struct archive *a, void const *buff,
		     size_t size, size_t read_size);
extern int archive_read_open_fd(struct archive *, int _fd,
		     size_t _block_size);

/* closing */
extern int		 archive_read_close(struct archive *);
extern int		 archive_format(struct archive *);

/* headers */
extern int archive_read_next_header2(struct archive *,
		     struct archive_entry *);
extern const struct stat	*archive_entry_stat(struct archive_entry *);
extern __LA_INT64_T		 archive_read_header_position(struct archive *);

/*
 * Set read options.
 */
/* Apply option to the format only. */
extern int archive_read_set_format_option(struct archive *_a,
			    const char *m, const char *o,
			    const char *v);
/* Apply option to the filter only. */
extern int archive_read_set_filter_option(struct archive *_a,
			    const char *m, const char *o,
			    const char *v);
/* Apply option to both the format and the filter. */
extern int archive_read_set_option(struct archive *_a,
			    const char *m, const char *o,
			    const char *v);
/* Apply option string to both the format and the filter. */
extern int archive_read_set_options(struct archive *_a,
			    const char *opts);

/*
 * Add a decryption passphrase.
 */
extern int archive_read_add_passphrase(struct archive *, const char *);
/* data */
extern int archive_read_data_skip(struct archive *);
extern int archive_read_data_into_fd(struct archive *, int fd);

#if ARCHIVE_VERSION_NUMBER < 4000000
extern int archive_read_support_compression_all(struct archive *);
extern int archive_read_support_compression_bzip2(struct archive *);
extern int archive_read_support_compression_compress(struct archive *);
extern int archive_read_support_compression_gzip(struct archive *);
extern int archive_read_support_compression_lzip(struct archive *);
extern int archive_read_support_compression_lzma(struct archive *);
extern int archive_read_support_compression_none(struct archive *);
extern int archive_read_support_compression_program(struct archive *, const char *command);
extern int archive_read_support_compression_program_signature
		(struct archive *, const char *,
		 const void * /* match */, size_t);

extern int archive_read_support_compression_rpm(struct archive *);
extern int archive_read_support_compression_uu(struct archive *);
extern int archive_read_support_compression_xz(struct archive *);
#endif

extern int archive_read_support_filter_all(struct archive *);
extern int archive_read_support_filter_bzip2(struct archive *);
extern int archive_read_support_filter_compress(struct archive *);
extern int archive_read_support_filter_gzip(struct archive *);
extern int archive_read_support_filter_grzip(struct archive *);
extern int archive_read_support_filter_lrzip(struct archive *);
extern int archive_read_support_filter_lz4(struct archive *);
extern int archive_read_support_filter_lzip(struct archive *);
extern int archive_read_support_filter_lzma(struct archive *);
extern int archive_read_support_filter_lzop(struct archive *);
extern int archive_read_support_filter_none(struct archive *);
extern int archive_read_support_filter_program(struct archive *,
		     const char *command);
extern int archive_read_support_filter_program_signature
		(struct archive *, const char * /* cmd */,
				    const void * /* match */, size_t);
extern int archive_read_support_filter_rpm(struct archive *);
extern int archive_read_support_filter_uu(struct archive *);
extern int archive_read_support_filter_xz(struct archive *);

extern int archive_read_support_format_7zip(struct archive *);
extern int archive_read_support_format_all(struct archive *);
extern int archive_read_support_format_ar(struct archive *);
extern int archive_read_support_format_by_code(struct archive *, int);
extern int archive_read_support_format_cab(struct archive *);
extern int archive_read_support_format_cpio(struct archive *);
extern int archive_read_support_format_empty(struct archive *);
extern int archive_read_support_format_gnutar(struct archive *);
extern int archive_read_support_format_iso9660(struct archive *);
extern int archive_read_support_format_lha(struct archive *);
/* extern int archive_read_support_format_mtree(struct archive *); */
extern int archive_read_support_format_rar(struct archive *);
extern int archive_read_support_format_raw(struct archive *);
extern int archive_read_support_format_tar(struct archive *);
extern int archive_read_support_format_warc(struct archive *);
extern int archive_read_support_format_xar(struct archive *);
/* archive_read_support_format_zip() enables both streamable and seekable
 * zip readers. */
extern int archive_read_support_format_zip(struct archive *);
/* Reads Zip archives as stream from beginning to end.  Doesn't
 * correctly handle SFX ZIP files or ZIP archives that have been modified
 * in-place. */
extern int archive_read_support_format_zip_streamable(struct archive *);
/* Reads starting from central directory; requires seekable input. */
extern int archive_read_support_format_zip_seekable(struct archive *);

/* Functions to manually set the format and filters to be used. This is
 * useful to bypass the bidding process when the format and filters to use
 * is known in advance.
 */
extern int archive_read_set_format(struct archive *, int);
extern int archive_read_append_filter(struct archive *, int);
extern int archive_read_append_filter_program(struct archive *,
    const char *);
extern int archive_read_append_filter_program_signature
    (struct archive *, const char *, const void * /* match */, size_t);

/* ARCHIVE WRITING */
extern struct archive	*archive_write_new(void);
extern int		 archive_write_free(struct archive *);

/* opening */
extern int archive_write_open(struct archive *, void *,
		     archive_open_callback *, archive_write_callback *,
		     archive_close_callback *);
extern int archive_write_open_fd(struct archive *, int _fd);
extern int archive_write_open_filename(struct archive *, const char *_file);
extern int archive_write_open_filename_w(struct archive *,
		     const wchar_t *_file);
extern int archive_write_open_memory(struct archive *,
			void *_buffer, size_t _buffSize, size_t *_used);

/* closing */
extern int		 archive_write_close(struct archive *);

/* headers */
extern int archive_write_header(struct archive *,
		     struct archive_entry *);

extern int archive_write_set_format_option(struct archive *_a,
			    const char *m, const char *o,
			    const char *v);
/* Apply option to the filter only. */
extern int archive_write_set_filter_option(struct archive *_a,
			    const char *m, const char *o,
			    const char *v);
/* Apply option to both the format and the filter. */
extern int archive_write_set_option(struct archive *_a,
			    const char *m, const char *o,
			    const char *v);
/* Apply option string to both the format and the filter. */
extern int archive_write_set_options(struct archive *_a,
			    const char *opts);

/* password */
extern int archive_write_set_passphrase(struct archive *_a, const char *p);
/* data */

/* commit */
extern int		 archive_write_finish_entry(struct archive *);

/* FILTERS */
extern int archive_write_add_filter(struct archive *, int filter_code);
extern int archive_write_add_filter_by_name(struct archive *,
		     const char *name);
extern int archive_write_add_filter_b64encode(struct archive *);
extern int archive_write_add_filter_bzip2(struct archive *);
extern int archive_write_add_filter_compress(struct archive *);
extern int archive_write_add_filter_grzip(struct archive *);
extern int archive_write_add_filter_gzip(struct archive *);
extern int archive_write_add_filter_lrzip(struct archive *);
extern int archive_write_add_filter_lz4(struct archive *);
extern int archive_write_add_filter_lzip(struct archive *);
extern int archive_write_add_filter_lzma(struct archive *);
extern int archive_write_add_filter_lzop(struct archive *);
extern int archive_write_add_filter_none(struct archive *);
extern int archive_write_add_filter_program(struct archive *,
		     const char *cmd);
extern int archive_write_add_filter_uuencode(struct archive *);
extern int archive_write_add_filter_xz(struct archive *);


/* A convenience function to set the format based on the code or name. */
extern int archive_write_set_format(struct archive *, int format_code);
extern int archive_write_set_format_by_name(struct archive *,
		     const char *name);
/* To minimize link pollution, use one or more of the following. */
extern int archive_write_set_format_7zip(struct archive *);
extern int archive_write_set_format_ar_bsd(struct archive *);
extern int archive_write_set_format_ar_svr4(struct archive *);
extern int archive_write_set_format_cpio(struct archive *);
extern int archive_write_set_format_cpio_newc(struct archive *);
extern int archive_write_set_format_gnutar(struct archive *);
extern int archive_write_set_format_iso9660(struct archive *);
extern int archive_write_set_format_mtree(struct archive *);
extern int archive_write_set_format_mtree_classic(struct archive *);
/* TODO: int archive_write_set_format_old_tar(struct archive *); */
extern int archive_write_set_format_pax(struct archive *);
extern int archive_write_set_format_pax_restricted(struct archive *);
extern int archive_write_set_format_raw(struct archive *);
extern int archive_write_set_format_shar(struct archive *);
extern int archive_write_set_format_shar_dump(struct archive *);
extern int archive_write_set_format_ustar(struct archive *);
extern int archive_write_set_format_v7tar(struct archive *);
extern int archive_write_set_format_warc(struct archive *);
extern int archive_write_set_format_xar(struct archive *);
extern int archive_write_set_format_zip(struct archive *);
extern int archive_write_set_format_filter_by_ext(struct archive *a, const char *filename);
extern int archive_write_set_format_filter_by_ext_def(struct archive *a, const char *filename, const char * def_ext);
extern int archive_write_zip_set_compression_deflate(struct archive *);
extern int archive_write_zip_set_compression_store(struct archive *);

/* ARCHIVE ENTRY */
extern struct archive_entry	*archive_entry_new(void);
extern void			 archive_entry_free(struct archive_entry *);

/* ARCHIVE ENTRY PROPERTY ACCESS */
/* reading */
extern const char	*archive_entry_pathname(struct archive_entry *);
extern const wchar_t	*archive_entry_pathname_w(struct archive_entry *);
extern __LA_INT64_T	 archive_entry_size(struct archive_entry *);
extern time_t            archive_entry_mtime(struct archive_entry *);
extern __LA_MODE_T	 archive_entry_filetype(struct archive_entry *);
extern __LA_MODE_T	 archive_entry_perm(struct archive_entry *);
extern const char	*archive_entry_symlink(struct archive_entry *);
//extern  const char	*archive_entry_symlink_utf8(struct archive_entry *);

extern void	archive_entry_set_link(struct archive_entry *, const char *);
//extern void	archive_entry_set_link_utf8(struct archive_entry *, const char *);
//extern int		 archive_entry_symlink_type(struct archive_entry *);
extern const wchar_t	*archive_entry_symlink_w(struct archive_entry *);

//extern void	archive_entry_copy_link(struct archive_entry *, const char *);
//extern void	archive_entry_copy_link_w(struct archive_entry *, const wchar_t *);

/* The names for symlink modes here correspond to an old BSD
 * command-line argument convention: -L, -P, -H */
/* Follow all symlinks. */
extern int archive_read_disk_set_symlink_logical(struct archive *);
/* Follow no symlinks. */
extern int archive_read_disk_set_symlink_physical(struct archive *);
/* Follow symlink initially, then not. */
extern int archive_read_disk_set_symlink_hybrid(struct archive *);


extern void	archive_entry_set_symlink(struct archive_entry *, const char *);
//extern void	archive_entry_set_symlink_type(struct archive_entry *, int);
//extern void	archive_entry_set_symlink_utf8(struct archive_entry *, const char *);
extern void	archive_entry_copy_symlink(struct archive_entry *, const char *);
extern void	archive_entry_copy_symlink_w(struct archive_entry *, const wchar_t *);
//extern int	archive_entry_update_symlink_utf8(struct archive_entry *, const char *);

/* writing */
extern void	archive_entry_set_pathname(struct archive_entry *, const char *);
extern void	archive_entry_set_size(struct archive_entry *, __LA_INT64_T);
extern void	archive_entry_set_mtime(struct archive_entry *, time_t, long);
extern void	archive_entry_set_filetype(struct archive_entry *, unsigned int);
extern void	archive_entry_set_perm(struct archive_entry *, __LA_MODE_T);
//extern void	archive_entry_set_link(struct archive_entry *, __LA_MODE_T);
//extern void	archive_entry_set_symlink(struct archive_entry *, __LA_MODE_T);


/* ERROR HANDLING */
extern int		 archive_errno(struct archive *);
extern const char	*archive_error_string(struct archive *);

extern int archive_version_number(void);
extern const char *archive_version_string(void);

/* CONSTANTS */

#define	ARCHIVE_EOF	  1	/* Found end of archive. */
#define	ARCHIVE_OK	  0	/* Operation was successful. */
#define	ARCHIVE_RETRY	(-10)	/* Retry might succeed. */
#define	ARCHIVE_WARN	(-20)	/* Partial success. */
#define	ARCHIVE_FAILED	(-25)	/* Current operation cannot complete. */
#define	ARCHIVE_FATAL	(-30)	/* No more operations are possible. */

#define	ARCHIVE_FILTER_NONE	0
#define	ARCHIVE_FILTER_GZIP	1
#define	ARCHIVE_FILTER_BZIP2	2
#define	ARCHIVE_FILTER_COMPRESS	3
#define	ARCHIVE_FILTER_PROGRAM	4
#define	ARCHIVE_FILTER_LZMA	5
#define	ARCHIVE_FILTER_XZ	6
#define	ARCHIVE_FILTER_UU	7
#define	ARCHIVE_FILTER_RPM	8
#define	ARCHIVE_FILTER_LZIP	9
#define	ARCHIVE_FILTER_LRZIP	10
#define	ARCHIVE_FILTER_LZOP	11
#define	ARCHIVE_FILTER_GRZIP	12
#define	ARCHIVE_FILTER_LZ4	13

#define	ARCHIVE_FORMAT_BASE_MASK		0xff0000
#define	ARCHIVE_FORMAT_CPIO			0x10000
#define	ARCHIVE_FORMAT_CPIO_POSIX		(ARCHIVE_FORMAT_CPIO | 1)
#define	ARCHIVE_FORMAT_CPIO_BIN_LE		(ARCHIVE_FORMAT_CPIO | 2)
#define	ARCHIVE_FORMAT_CPIO_BIN_BE		(ARCHIVE_FORMAT_CPIO | 3)
#define	ARCHIVE_FORMAT_CPIO_SVR4_NOCRC		(ARCHIVE_FORMAT_CPIO | 4)
#define	ARCHIVE_FORMAT_CPIO_SVR4_CRC		(ARCHIVE_FORMAT_CPIO | 5)
#define	ARCHIVE_FORMAT_CPIO_AFIO_LARGE		(ARCHIVE_FORMAT_CPIO | 6)
#define	ARCHIVE_FORMAT_SHAR			0x20000
#define	ARCHIVE_FORMAT_SHAR_BASE		(ARCHIVE_FORMAT_SHAR | 1)
#define	ARCHIVE_FORMAT_SHAR_DUMP		(ARCHIVE_FORMAT_SHAR | 2)
#define	ARCHIVE_FORMAT_TAR			0x30000
#define	ARCHIVE_FORMAT_TAR_USTAR		(ARCHIVE_FORMAT_TAR | 1)
#define	ARCHIVE_FORMAT_TAR_PAX_INTERCHANGE	(ARCHIVE_FORMAT_TAR | 2)
#define	ARCHIVE_FORMAT_TAR_PAX_RESTRICTED	(ARCHIVE_FORMAT_TAR | 3)
#define	ARCHIVE_FORMAT_TAR_GNUTAR		(ARCHIVE_FORMAT_TAR | 4)
#define	ARCHIVE_FORMAT_ISO9660			0x40000
#define	ARCHIVE_FORMAT_ISO9660_ROCKRIDGE	(ARCHIVE_FORMAT_ISO9660 | 1)
#define	ARCHIVE_FORMAT_ZIP			0x50000
#define	ARCHIVE_FORMAT_EMPTY			0x60000
#define	ARCHIVE_FORMAT_AR			0x70000
#define	ARCHIVE_FORMAT_AR_GNU			(ARCHIVE_FORMAT_AR | 1)
#define	ARCHIVE_FORMAT_AR_BSD			(ARCHIVE_FORMAT_AR | 2)
#define	ARCHIVE_FORMAT_MTREE			0x80000
#define	ARCHIVE_FORMAT_RAW			0x90000
#define	ARCHIVE_FORMAT_XAR			0xA0000
#define	ARCHIVE_FORMAT_LHA			0xB0000
#define	ARCHIVE_FORMAT_CAB			0xC0000
#define	ARCHIVE_FORMAT_RAR			0xD0000
#define	ARCHIVE_FORMAT_7ZIP			0xE0000
#define	ARCHIVE_FORMAT_WARC			0xF0000

/* Default: Do not try to set owner/group. */
#define	ARCHIVE_EXTRACT_OWNER			(0x0001)
/* Default: Do obey umask, do not restore SUID/SGID/SVTX bits. */
#define	ARCHIVE_EXTRACT_PERM			(0x0002)
/* Default: Do not restore mtime/atime. */
#define	ARCHIVE_EXTRACT_TIME			(0x0004)
/* Default: Replace existing files. */
#define	ARCHIVE_EXTRACT_NO_OVERWRITE 		(0x0008)
/* Default: Try create first, unlink only if create fails with EEXIST. */
#define	ARCHIVE_EXTRACT_UNLINK			(0x0010)
/* Default: Do not restore ACLs. */
#define	ARCHIVE_EXTRACT_ACL			(0x0020)
/* Default: Do not restore fflags. */
#define	ARCHIVE_EXTRACT_FFLAGS			(0x0040)
/* Default: Do not restore xattrs. */
#define	ARCHIVE_EXTRACT_XATTR 			(0x0080)
/* Default: Do not try to guard against extracts redirected by symlinks. */
/* Note: With ARCHIVE_EXTRACT_UNLINK, will remove any intermediate symlink. */
#define	ARCHIVE_EXTRACT_SECURE_SYMLINKS		(0x0100)
/* Default: Do not reject entries with '..' as path elements. */
#define	ARCHIVE_EXTRACT_SECURE_NODOTDOT		(0x0200)
/* Default: Create parent directories as needed. */
#define	ARCHIVE_EXTRACT_NO_AUTODIR		(0x0400)
/* Default: Overwrite files, even if one on disk is newer. */
#define	ARCHIVE_EXTRACT_NO_OVERWRITE_NEWER	(0x0800)
/* Detect blocks of 0 and write holes instead. */
#define	ARCHIVE_EXTRACT_SPARSE			(0x1000)
/* Default: Do not restore Mac extended metadata. */
/* This has no effect except on Mac OS. */
#define	ARCHIVE_EXTRACT_MAC_METADATA		(0x2000)
/* Default: Use HFS+ compression if it was compressed. */
/* This has no effect except on Mac OS v10.6 or later. */
#define	ARCHIVE_EXTRACT_NO_HFS_COMPRESSION	(0x4000)
/* Default: Do not use HFS+ compression if it was not compressed. */
/* This has no effect except on Mac OS v10.6 or later. */
#define	ARCHIVE_EXTRACT_HFS_COMPRESSION_FORCED	(0x8000)
/* Default: Do not reject entries with absolute paths */
#define ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS (0x10000)
/* Default: Do not clear no-change flags when unlinking object */
#define	ARCHIVE_EXTRACT_CLEAR_NOCHANGE_FFLAGS	(0x20000)


%inline %{

PyObject *archive_read_data_into_str(struct archive *archive, int len) {
    PyObject *str = NULL;
    if (!(str = PyBytes_FromStringAndSize(NULL, len))) {
        PyErr_SetString(PyExc_MemoryError, "could not allocate string.");
        return NULL;
    }
    if (len != archive_read_data(archive, PyBytes_AS_STRING(str), len)) {
        PyErr_SetString(PyExc_RuntimeError, "could not read requested data.");
        return NULL;
    }
    return str;
}

PyObject *archive_write_data_from_str(struct archive *archive, PyObject *str) {
    Py_ssize_t len = PyBytes_Size(str);
 
    if (!archive_write_data(archive, PyBytes_AS_STRING(str), len)) {
        PyErr_SetString(PyExc_RuntimeError, "could not write requested data.");
        return NULL;
    }
    return PyInt_FromLong(len);
}
%}