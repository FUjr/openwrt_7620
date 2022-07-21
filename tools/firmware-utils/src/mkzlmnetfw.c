/*
 *  Copyright (C) 2017 Lamon Zhang <980741357@qq.com>
 
 *  from  fix-u-media-header.c  Gabor Juhos <juhosg@openwrt.org>
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License version 2 as published
 *  by the Free Software Foundation.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>     /* for unlink() */
#include <libgen.h>
#include <getopt.h>     /* for getopt() */
#include <stdarg.h>
#include <errno.h>
#include <sys/stat.h>

#include "cyg_crc.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#define IH_MAGIC	0x27051956	/* Image Magic Number		*/
#define IH_NMLEN	(32-4)		/* Image Name Length		*/

#define IMAGENAME "ZLMnet?MIFIF17N"
#define IMAGENAMELEN 15
#define STEPPAD 11



struct zlmnet_image_header {
	uint32_t	ih_magic;	/* Image Header Magic Number	*/
	uint32_t	ih_hcrc;	/* Image Header CRC Checksum	*/
	uint32_t	ih_time;	/* Image Creation Timestamp	*/
	uint32_t	ih_size;	/* Image Data Size		*/
	uint32_t	ih_load;	/* Data	 Load  Address		*/
	uint32_t	ih_ep;		/* Entry Point Address		*/
	uint32_t	ih_dcrc;	/* Image Data CRC Checksum	*/
	uint8_t		ih_os;		/* Operating System		*/
	uint8_t		ih_arch;	/* CPU architecture		*/
	uint8_t		ih_type;	/* Image Type			*/
	uint8_t		ih_comp;	/* Compression Type		*/
	uint8_t		ih_name[IH_NMLEN];	/* Image Name		*/
	uint32_t	ih_ksz;		/* Kernel Part Size		*/
} __attribute__ ((packed));

struct if_info {
	char		*file_name;	/* name of the file */
	uint32_t	file_size;	/* length of the file */
};

static char *progname;
static char *ofname;
static struct if_info if_info;
static uint8_t image_type;

/*
 * Message macros
 */
#define ERR(fmt, ...) do { \
	fflush(0); \
	fprintf(stderr, "[%s] *** error: " fmt "\n", \
			progname, ## __VA_ARGS__ ); \
} while (0)

#define ERRS(fmt, ...) do { \
	int save = errno; \
	fflush(0); \
	fprintf(stderr, "[%s] *** error: " fmt " (%s)\n", \
			progname, ## __VA_ARGS__, strerror(save)); \
} while (0)

#define DBG(fmt, ...) do { \
	fprintf(stderr, "[%s] " fmt "\n", progname, ## __VA_ARGS__ ); \
} while (0)

static void usage(int status)
{
	FILE *stream = (status != EXIT_SUCCESS) ? stderr : stdout;

	fprintf(stream, "Usage: %s [OPTIONS...]\n", progname);
	fprintf(stream,
"\n"
"Options:\n"
"  -i <file>       read input from the file <file>\n"
"  -o <file>       write output to the file <file>\n"
"  -h              show this help\n"
	);

	exit(status);
}

static int str2u32(char *arg, uint32_t *val)
{
	char *err = NULL;
	uint32_t t;

	errno=0;
	t = strtoul(arg, &err, 0);
	if (errno || (err==arg) || ((err != NULL) && *err)) {
		return -1;
	}

	*val = t;
	return 0;
}

static int str2u8(char *arg, uint8_t *val)
{
	char *err = NULL;
	uint32_t t;

	errno=0;
	t = strtoul(arg, &err, 0);
	if (errno || (err==arg) || ((err != NULL) && *err)) {
		return -1;
	}

	if (t > 255)
		return -1;

	*val = t;
	return 0;
}

static int get_file_stat(struct if_info *fdata)
{
	struct stat st;
	int res;

	if (fdata->file_name == NULL)
		return 0;

	res = stat(fdata->file_name, &st);
	if (res){
		ERRS("stat failed on %s", fdata->file_name);
		return res;
	}

	fdata->file_size = st.st_size;
	return 0;
}

static int read_to_buf(struct if_info *fdata, char *buf)
{
	FILE *f;
	int ret = EXIT_FAILURE;

	f = fopen(fdata->file_name, "r");
	if (f == NULL) {
		ERRS("could not open \"%s\" for reading", fdata->file_name);
		goto out;
	}

	errno = 0;
	fread(buf, fdata->file_size, 1, f);
	if (errno != 0) {
		ERRS("unable to read from file \"%s\"", fdata->file_name);
		goto out_close;
	}

	ret = EXIT_SUCCESS;

out_close:
	fclose(f);
out:
	return ret;
}

static int check_options(void)
{
	int ret;

	if (ofname == NULL) {
		ERR("no %s specified", "output file");
		return -1;
	}

	if (if_info.file_name == NULL) {
		ERR("no %s specified", "input file");
		return -1;
	}

	ret = get_file_stat(&if_info);
	if (ret)
		return ret;

	return 0;
}

static int write_fw(char *data, int len)
{
	FILE *f;
	int ret = EXIT_FAILURE;

	f = fopen(ofname, "w");
	if (f == NULL) {
		ERRS("could not open \"%s\" for writing", ofname);
		goto out;
	}

	errno = 0;
	fwrite(data, len, 1, f);
	if (errno) {
		ERRS("unable to write output file");
		goto out_flush;
	}

	ret = EXIT_SUCCESS;

out_flush:
	fflush(f);
	fclose(f);
	if (ret != EXIT_SUCCESS) {
		unlink(ofname);
	}
out:
	return ret;
}

static int fix_header(void)
{
	int buflen;
	char *buf;
	uint32_t crc, crc_orig;
	struct zlmnet_image_header * hdr;
	int ret = EXIT_FAILURE;

	buflen = if_info.file_size;
	if (buflen < sizeof(*hdr)) {
		ERR("invalid input file\n");
		return ret;
	}

	buf = malloc(buflen);
	if (!buf) {
		ERR("no memory for buffer\n");
		goto out;
	}

	ret = read_to_buf(&if_info, buf);
	if (ret)
		goto out_free_buf;

	hdr = (struct zlmnet_image_header *)buf;
	if (ntohl(hdr->ih_magic) != IH_MAGIC) {
		ERR("invalid input file, bad magic\n");
		goto out_free_buf;
	}

	/* verify header CRC */
	crc_orig = ntohl(hdr->ih_hcrc);
	hdr->ih_hcrc = 0;
	crc = cyg_ether_crc32((unsigned char *)hdr, sizeof(*hdr));
	if (crc != crc_orig) {
		ERR("invalid input file, bad header CRC\n");
		goto out_free_buf;
	}

	hdr->ih_name[IH_NMLEN - 1] = '\0';

  /* ZLMnet image header fix */
  if(strncmp(hdr->ih_name, IMAGENAME, IMAGENAMELEN))
  {
		hdr->ih_size  = htonl(ntohl(hdr->ih_size) + STEPPAD);
		
		memset(hdr->ih_name, 0 , IH_NMLEN);

		strncpy((char *)hdr->ih_name, IMAGENAME, IH_NMLEN);

  }

	/* update header CRC */
	crc = cyg_ether_crc32((unsigned char *)hdr, sizeof(*hdr));
	hdr->ih_hcrc = htonl(crc);

	ret = write_fw(buf, buflen);
	if (ret)
		goto out_free_buf;


	ret = EXIT_SUCCESS;

out_free_buf:
	free(buf);
out:
	return ret;
}

int main(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;

	progname = basename(argv[0]);

	while (1) {
		int c;

		c = getopt(argc, argv, "i:o:h");
		if (c == -1)
			break;

		switch (c) {
		case 'i':
			if_info.file_name = optarg;
			break;
		case 'o':
			ofname = optarg;
			break;
		case 'h':
			usage(EXIT_SUCCESS);
			break;
		default:
			usage(EXIT_FAILURE);
			break;
		}
	}

	ret = check_options();
	if (ret)
		goto out;

	ret = fix_header();

out:
	return ret;
}
