/*
 * aap_cvi - see aap_cvi.h. Built by build.rs with the `cvi` cargo feature,
 * against the cvi_mpi headers (CVI_MPI_INC) and linked with libsys/libvenc/libvdec.
 *
 * The code follows the flow of milkv-duos-hwcodec-test (cvi_codec_test.c),
 * which is verified on a Milk-V Duo S, including its pitfalls:
 *   - VB_BLK is a 64-bit kernel pointer on riscv64: never squeeze it into an int;
 *   - the encoder owns the input block until the matching stream was fetched,
 *     so blocks are released only after CVI_VENC_GetStream succeeded;
 *   - libsys needs libatomic (linked by build.rs).
 */
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cvi_buffer.h"
#include "cvi_sys.h"
#include "cvi_vb.h"
#include "cvi_vdec.h"
#include "cvi_venc.h"

#include "aap_cvi.h"

#define PIX_FMT PIXEL_FORMAT_YUV_PLANAR_420 /* I420 */
#define AAP_MAX_CHN 4 /* channels probed; the kernel module limits them (MaxVencChnNum/MaxVdecChnNum) */
#define AAP_ENC_INFLIGHT 4 /* input blocks the encoder may still own (after stream timeouts) */

/* ------------------------------------------------------------------ errors */

static __thread char g_err[192];

static void set_err(const char *what, CVI_S32 ret)
{
	snprintf(g_err, sizeof(g_err), "%s -> 0x%x", what, (unsigned)ret);
}

static void set_msg(const char *msg)
{
	snprintf(g_err, sizeof(g_err), "%s", msg);
}

const char *aap_cvi_last_error(void)
{
	return g_err;
}

/* ------------------------------------------------------------------- SYS/VB */

/*
 * libvenc/libvdec/libsys keep unprotected per-process state (fd tables,
 * channel counters), so channel creation/destruction and SYS init are
 * serialised with one lock. Data-path calls (send/get) are per channel.
 */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_sys_ready;
static CVI_U32 g_blk_size;
static int g_enc_used[AAP_MAX_CHN];
static int g_dec_used[AAP_MAX_CHN];

static CVI_U32 enc_blk_size(unsigned w, unsigned h)
{
	VB_CAL_CONFIG_S cfg;

	memset(&cfg, 0, sizeof(cfg));
	VENC_GetPicBufferConfig(w, h, PIX_FMT, DATA_BITWIDTH_8, COMPRESS_MODE_NONE, &cfg);
	return cfg.u32VBSize;
}

static CVI_U32 dec_blk_size(unsigned w, unsigned h)
{
	return VDEC_GetPicBufferSize(PT_H264, w, h, PIX_FMT, DATA_BITWIDTH_8, COMPRESS_MODE_NONE);
}

int aap_cvi_sys_init(unsigned max_w, unsigned max_h, unsigned blk_cnt)
{
	VB_CONFIG_S vb;
	CVI_U32 sz, e, d;
	CVI_S32 r;
	int ret = AAP_CVI_ERR;

	pthread_mutex_lock(&g_lock);
	if (g_sys_ready) {
		ret = AAP_CVI_OK;
		goto out;
	}

	e = enc_blk_size(max_w, max_h);
	d = dec_blk_size(max_w, max_h);
	sz = e > d ? e : d;

	memset(&vb, 0, sizeof(vb));
	vb.u32MaxPoolCnt = 1;
	vb.astCommPool[0].u32BlkSize = sz;
	vb.astCommPool[0].u32BlkCnt = blk_cnt;
	vb.astCommPool[0].enRemapMode = VB_REMAP_MODE_CACHED;

	/* start from a clean state, like the SDK samples */
	CVI_SYS_Exit();
	CVI_VB_Exit();
	r = CVI_VB_SetConfig(&vb);
	if (r != CVI_SUCCESS) {
		set_err("CVI_VB_SetConfig", r);
		goto out;
	}
	r = CVI_VB_Init();
	if (r != CVI_SUCCESS) {
		set_err("CVI_VB_Init", r);
		goto out;
	}
	r = CVI_SYS_Init();
	if (r != CVI_SUCCESS) {
		set_err("CVI_SYS_Init", r);
		CVI_VB_Exit();
		goto out;
	}
	g_blk_size = sz;
	g_sys_ready = 1;
	ret = AAP_CVI_OK;
out:
	pthread_mutex_unlock(&g_lock);
	return ret;
}

/* ------------------------------------------------------------------ encoder */

struct aap_cvi_enc {
	int chn;
	unsigned w, h;
	VB_CAL_CONFIG_S cfg;
	VB_BLK inflight[AAP_ENC_INFLIGHT]; /* FIFO, oldest first */
	int n_inflight;
	VENC_PACK_S *packs;
	unsigned packs_cap;
	uint8_t *out;
	size_t out_cap;
};

int aap_cvi_enc_open(aap_cvi_enc **out, unsigned w, unsigned h, unsigned gop, unsigned bitrate_kbps,
		     unsigned fps, unsigned profile)
{
	aap_cvi_enc *e;
	VENC_CHN_ATTR_S a;
	VENC_RECV_PIC_PARAM_S rp;
	CVI_S32 r = CVI_FAILURE;
	int chn, found = -1;

	*out = NULL;
	if (!g_sys_ready) {
		set_msg("aap_cvi_enc_open: SYS not initialised");
		return AAP_CVI_ERR;
	}
	if (enc_blk_size(w, h) > g_blk_size) {
		set_msg("encoder frame does not fit the VB pool (picture larger than configured maximum)");
		return AAP_CVI_ERR;
	}
	if (!fps)
		fps = 30;
	if (!gop)
		gop = 30;

	e = calloc(1, sizeof(*e));
	if (!e)
		return AAP_CVI_ERR;
	e->w = w;
	e->h = h;
	VENC_GetPicBufferConfig(w, h, PIX_FMT, DATA_BITWIDTH_8, COMPRESS_MODE_NONE, &e->cfg);

	memset(&a, 0, sizeof(a));
	a.stVencAttr.enType = PT_H264;
	a.stVencAttr.u32MaxPicWidth = w;
	a.stVencAttr.u32MaxPicHeight = h;
	a.stVencAttr.u32PicWidth = w;
	a.stVencAttr.u32PicHeight = h;
	a.stVencAttr.u32BufSize = 0x100000;
	a.stVencAttr.u32Profile = profile; /* 0 baseline, 1 main, 2 high */
	a.stVencAttr.bByFrame = CVI_TRUE;
	a.stVencAttr.bEsBufQueueEn = CVI_TRUE;
	a.stGopAttr.enGopMode = VENC_GOPMODE_NORMALP; /* no B-frames: output order == input order */
	a.stGopAttr.stNormalP.s32IPQpDelta = 2;

	a.stRcAttr.enRcMode = VENC_RC_MODE_H264CBR;
	a.stRcAttr.stH264Cbr.u32Gop = gop;
	a.stRcAttr.stH264Cbr.u32StatTime = 0;
	a.stRcAttr.stH264Cbr.u32SrcFrameRate = fps;
	a.stRcAttr.stH264Cbr.fr32DstFrameRate = fps;
	a.stRcAttr.stH264Cbr.bVariFpsEn = 0;
	a.stRcAttr.stH264Cbr.u32BitRate = bitrate_kbps; /* kbit/s */

	pthread_mutex_lock(&g_lock);
	for (chn = 0; chn < AAP_MAX_CHN; chn++) {
		if (g_enc_used[chn])
			continue;
		r = CVI_VENC_CreateChn(chn, &a);
		if (r == CVI_SUCCESS) {
			g_enc_used[chn] = 1;
			found = chn;
			break;
		}
	}
	if (found >= 0) {
		rp.s32RecvPicNum = -1;
		r = CVI_VENC_StartRecvFrame(found, &rp);
		if (r != CVI_SUCCESS) {
			CVI_VENC_DestroyChn(found);
			g_enc_used[found] = 0;
			found = -1;
		}
	}
	pthread_mutex_unlock(&g_lock);

	if (found < 0) {
		set_err("CVI_VENC_CreateChn/StartRecvFrame", r);
		free(e);
		return AAP_CVI_ERR;
	}
	e->chn = found;
	*out = e;
	return AAP_CVI_OK;
}

void aap_cvi_enc_close(aap_cvi_enc *e)
{
	int i;

	if (!e)
		return;
	pthread_mutex_lock(&g_lock);
	CVI_VENC_StopRecvFrame(e->chn);
	CVI_VENC_ResetChn(e->chn);
	CVI_VENC_DestroyChn(e->chn);
	g_enc_used[e->chn] = 0;
	pthread_mutex_unlock(&g_lock);
	for (i = 0; i < e->n_inflight; i++)
		CVI_VB_ReleaseBlock(e->inflight[i]);
	free(e->packs);
	free(e->out);
	free(e);
}

int aap_cvi_enc_request_idr(aap_cvi_enc *e)
{
	CVI_S32 r = CVI_VENC_RequestIDR(e->chn, CVI_TRUE);

	if (r != CVI_SUCCESS) {
		set_err("CVI_VENC_RequestIDR", r);
		return AAP_CVI_ERR;
	}
	return AAP_CVI_OK;
}

static void enc_release_oldest(aap_cvi_enc *e)
{
	if (e->n_inflight > 0) {
		CVI_VB_ReleaseBlock(e->inflight[0]);
		memmove(&e->inflight[0], &e->inflight[1], (e->n_inflight - 1) * sizeof(e->inflight[0]));
		e->n_inflight--;
	}
}

/* Allocate a VB block, copy the I420 frame into it and hand it to the encoder. */
static int enc_send(aap_cvi_enc *e, const uint8_t *src_y, const uint8_t *src_u, const uint8_t *src_v,
		    int timeout_ms)
{
	VIDEO_FRAME_INFO_S fi;
	VIDEO_FRAME_S *f = &fi.stVFrame;
	const VB_CAL_CONFIG_S *cfg = &e->cfg;
	VB_BLK blk;
	CVI_U32 len[3];
	uint8_t *va[3] = { NULL, NULL, NULL };
	CVI_S32 r;
	unsigned j, i;

	blk = CVI_VB_GetBlock(VB_INVALID_POOLID, cfg->u32VBSize);
	if (blk == VB_INVALID_HANDLE) {
		set_msg("CVI_VB_GetBlock failed (VB pool exhausted)");
		return AAP_CVI_ERR;
	}

	memset(&fi, 0, sizeof(fi));
	fi.u32PoolId = CVI_VB_Handle2PoolId(blk);
	f->enCompressMode = COMPRESS_MODE_NONE;
	f->enPixelFormat = PIX_FMT;
	f->enVideoFormat = VIDEO_FORMAT_LINEAR;
	f->enColorGamut = COLOR_GAMUT_BT709;
	f->enDynamicRange = DYNAMIC_RANGE_SDR8;
	f->u32Width = e->w;
	f->u32Height = e->h;

	len[0] = cfg->u32MainYSize;
	len[1] = cfg->u32MainCSize;
	len[2] = cfg->u32MainCSize;
	f->u64PhyAddr[0] = CVI_VB_Handle2PhysAddr(blk);
	f->u64PhyAddr[1] = ALIGN(f->u64PhyAddr[0] + cfg->u32MainYSize, cfg->u16AddrAlign);
	f->u64PhyAddr[2] = ALIGN(f->u64PhyAddr[1] + cfg->u32MainCSize, cfg->u16AddrAlign);
	f->u32Stride[0] = cfg->u32MainStride;
	f->u32Stride[1] = cfg->u32CStride;
	f->u32Stride[2] = cfg->u32CStride;
	for (i = 0; i < 3; i++) {
		f->u32Length[i] = len[i];
		va[i] = CVI_SYS_MmapCache(f->u64PhyAddr[i], len[i]);
		if (!va[i]) {
			set_msg("CVI_SYS_MmapCache failed (encoder input plane)");
			goto fail;
		}
		f->pu8VirAddr[i] = va[i];
	}

	for (j = 0; j < e->h; j++)
		memcpy(va[0] + (size_t)j * f->u32Stride[0], src_y + (size_t)j * e->w, e->w);
	for (j = 0; j < e->h / 2; j++) {
		memcpy(va[1] + (size_t)j * f->u32Stride[1], src_u + (size_t)j * (e->w / 2), e->w / 2);
		memcpy(va[2] + (size_t)j * f->u32Stride[2], src_v + (size_t)j * (e->w / 2), e->w / 2);
	}
	for (i = 0; i < 3; i++)
		CVI_SYS_IonFlushCache(f->u64PhyAddr[i], va[i], len[i]);

	r = CVI_VENC_SendFrame(e->chn, &fi, timeout_ms);
	for (i = 0; i < 3; i++)
		CVI_SYS_Munmap(va[i], len[i]);
	if (r != CVI_SUCCESS) {
		set_err("CVI_VENC_SendFrame", r);
		CVI_VB_ReleaseBlock(blk);
		return AAP_CVI_ERR;
	}
	/* the encoder owns the block until the matching stream was fetched */
	e->inflight[e->n_inflight++] = blk;
	return AAP_CVI_OK;

fail:
	for (i = 0; i < 3; i++)
		if (va[i])
			CVI_SYS_Munmap(va[i], len[i]);
	CVI_VB_ReleaseBlock(blk);
	return AAP_CVI_ERR;
}

int aap_cvi_enc_encode(aap_cvi_enc *e, const uint8_t *y, const uint8_t *u, const uint8_t *v,
		       int timeout_ms, const uint8_t **out, size_t *out_len)
{
	VENC_CHN_STATUS_S st;
	VENC_STREAM_S s;
	CVI_S32 r;
	size_t total = 0;
	CVI_U32 i;
	int rc;

	*out = NULL;
	*out_len = 0;

	if (e->n_inflight >= AAP_ENC_INFLIGHT) {
		set_msg("encoder backlog: previous frames were never returned");
		return AAP_CVI_ERR;
	}
	rc = enc_send(e, y, u, v, timeout_ms);
	if (rc != AAP_CVI_OK)
		return rc;

	memset(&st, 0, sizeof(st));
	r = CVI_VENC_QueryStatus(e->chn, &st);
	if (r != CVI_SUCCESS) {
		set_err("CVI_VENC_QueryStatus", r);
		return AAP_CVI_ERR;
	}
	if (st.u32CurPacks < 8)
		st.u32CurPacks = 8;
	if (st.u32CurPacks > e->packs_cap) {
		VENC_PACK_S *np = realloc(e->packs, st.u32CurPacks * sizeof(*np));

		if (!np) {
			set_msg("out of memory");
			return AAP_CVI_ERR;
		}
		e->packs = np;
		e->packs_cap = st.u32CurPacks;
	}
	memset(e->packs, 0, e->packs_cap * sizeof(VENC_PACK_S));
	memset(&s, 0, sizeof(s));
	s.pstPack = e->packs;

	r = CVI_VENC_GetStream(e->chn, &s, timeout_ms);
	if (r == CVI_ERR_VENC_BUF_EMPTY || r == CVI_ERR_VENC_BUSY) {
		set_err("CVI_VENC_GetStream (timeout)", r);
		return AAP_CVI_TIMEOUT;
	}
	if (r != CVI_SUCCESS) {
		set_err("CVI_VENC_GetStream", r);
		return AAP_CVI_ERR;
	}

	for (i = 0; i < s.u32PackCount; i++)
		total += s.pstPack[i].u32Len - s.pstPack[i].u32Offset;
	if (total > e->out_cap) {
		uint8_t *nb = realloc(e->out, total);

		if (!nb) {
			CVI_VENC_ReleaseStream(e->chn, &s);
			enc_release_oldest(e);
			set_msg("out of memory");
			return AAP_CVI_ERR;
		}
		e->out = nb;
		e->out_cap = total;
	}
	total = 0;
	for (i = 0; i < s.u32PackCount; i++) {
		VENC_PACK_S *p = &s.pstPack[i];
		size_t n = p->u32Len - p->u32Offset;

		memcpy(e->out + total, p->pu8Addr + p->u32Offset, n);
		total += n;
	}
	CVI_VENC_ReleaseStream(e->chn, &s);
	enc_release_oldest(e);

	*out = e->out;
	*out_len = total;
	return AAP_CVI_OK;
}

/* ------------------------------------------------------------------ decoder */

struct aap_cvi_dec {
	int chn;
	unsigned w, h; /* maximum picture size of the channel */
	VIDEO_FRAME_INFO_S held;
	int have_held;
};

int aap_cvi_dec_open(aap_cvi_dec **out, unsigned w, unsigned h, unsigned display_frames)
{
	aap_cvi_dec *d;
	VDEC_CHN_ATTR_S a;
	VDEC_CHN_PARAM_S p;
	CVI_S32 r = CVI_FAILURE;
	const char *what = "CVI_VDEC_CreateChn";
	int chn, found = -1;

	*out = NULL;
	if (!g_sys_ready) {
		set_msg("aap_cvi_dec_open: SYS not initialised");
		return AAP_CVI_ERR;
	}
	if (dec_blk_size(w, h) > g_blk_size) {
		set_msg("decoder frame does not fit the VB pool (picture larger than configured maximum)");
		return AAP_CVI_ERR;
	}
	if (display_frames > 16)
		display_frames = 16;

	d = calloc(1, sizeof(*d));
	if (!d)
		return AAP_CVI_ERR;
	d->w = w;
	d->h = h;

	memset(&a, 0, sizeof(a));
	a.enType = PT_H264;
	a.enMode = VIDEO_MODE_FRAME; /* exactly one access unit per SendStream */
	a.u32PicWidth = w;
	a.u32PicHeight = h;
	a.u32StreamBufSize = ALIGN(w * h, 0x4000);
	a.u32FrameBufCnt = display_frames + 2;

	pthread_mutex_lock(&g_lock);
	for (chn = 0; chn < AAP_MAX_CHN; chn++) {
		if (g_dec_used[chn])
			continue;
		r = CVI_VDEC_CreateChn(chn, &a);
		if (r == CVI_SUCCESS) {
			g_dec_used[chn] = 1;
			found = chn;
			break;
		}
	}
	if (found >= 0) {
		what = "CVI_VDEC_GetChnParam/SetChnParam/StartRecvStream";
		r = CVI_VDEC_GetChnParam(found, &p);
		if (r == CVI_SUCCESS) {
			p.enPixelFormat = PIX_FMT;
			p.u32DisplayFrameNum = display_frames;
			r = CVI_VDEC_SetChnParam(found, &p);
		}
		if (r == CVI_SUCCESS)
			r = CVI_VDEC_StartRecvStream(found);
		if (r != CVI_SUCCESS) {
			CVI_VDEC_DestroyChn(found);
			g_dec_used[found] = 0;
			found = -1;
		}
	}
	pthread_mutex_unlock(&g_lock);

	if (found < 0) {
		set_err(what, r);
		free(d);
		return AAP_CVI_ERR;
	}
	d->chn = found;
	*out = d;
	return AAP_CVI_OK;
}

void aap_cvi_dec_close(aap_cvi_dec *d)
{
	if (!d)
		return;
	if (d->have_held)
		CVI_VDEC_ReleaseFrame(d->chn, &d->held);
	pthread_mutex_lock(&g_lock);
	CVI_VDEC_StopRecvStream(d->chn);
	CVI_VDEC_ResetChn(d->chn);
	CVI_VDEC_DestroyChn(d->chn);
	g_dec_used[d->chn] = 0;
	pthread_mutex_unlock(&g_lock);
	free(d);
}

int aap_cvi_dec_send(aap_cvi_dec *d, const uint8_t *au, size_t len, uint64_t pts, int timeout_ms)
{
	VDEC_STREAM_S s;
	CVI_S32 r;

	memset(&s, 0, sizeof(s));
	s.u64PTS = pts;
	s.pu8Addr = (CVI_U8 *)au;
	s.u32Len = len;
	s.bEndOfFrame = CVI_TRUE;
	s.bEndOfStream = CVI_FALSE;
	s.bDisplay = 1;
	r = CVI_VDEC_SendStream(d->chn, &s, timeout_ms);
	if (r != CVI_SUCCESS) {
		set_err("CVI_VDEC_SendStream", r);
		return AAP_CVI_ERR;
	}
	return AAP_CVI_OK;
}

void aap_cvi_dec_drop(aap_cvi_dec *d)
{
	if (d->have_held) {
		CVI_VDEC_ReleaseFrame(d->chn, &d->held);
		d->have_held = 0;
	}
}

int aap_cvi_dec_get(aap_cvi_dec *d, int timeout_ms, unsigned *w, unsigned *h)
{
	VIDEO_FRAME_INFO_S nf;
	CVI_S32 r;

	memset(&nf, 0, sizeof(nf));
	r = CVI_VDEC_GetFrame(d->chn, &nf, timeout_ms);
	if (r != CVI_SUCCESS) {
		/* a frame fetched earlier stays held: the caller may still take it */
		if (r == CVI_ERR_VDEC_BUSY || r == CVI_ERR_VDEC_BUF_EMPTY)
			return AAP_CVI_AGAIN;
		set_err("CVI_VDEC_GetFrame", r);
		return AAP_CVI_ERR;
	}
	/* newest frame wins: release the one that was still held */
	aap_cvi_dec_drop(d);
	d->held = nf;
	d->have_held = 1;
	*w = d->held.stVFrame.u32Width;
	*h = d->held.stVFrame.u32Height;
	return AAP_CVI_OK;
}

int aap_cvi_dec_take(aap_cvi_dec *d, uint8_t *dst_y, uint8_t *dst_u, uint8_t *dst_v)
{
	VIDEO_FRAME_S *f;
	uint8_t *va[3] = { NULL, NULL, NULL };
	int mapped[3] = { 0, 0, 0 };
	CVI_U32 maplen[3] = { 0, 0, 0 };
	unsigned w, h, i, j;
	int nv12, rc = AAP_CVI_ERR;

	if (!d->have_held) {
		set_msg("aap_cvi_dec_take without a frame");
		return AAP_CVI_ERR;
	}
	f = &d->held.stVFrame;
	w = f->u32Width;
	h = f->u32Height;

	if (f->enPixelFormat == PIXEL_FORMAT_NV12 || f->enPixelFormat == PIXEL_FORMAT_NV21) {
		nv12 = 1;
	} else if (f->enPixelFormat == PIX_FMT) {
		nv12 = 0;
	} else {
		char msg[96];

		snprintf(msg, sizeof(msg), "unsupported decoder pixel format %d", (int)f->enPixelFormat);
		set_msg(msg);
		goto out;
	}

	for (i = 0; i < (nv12 ? 2u : 3u); i++) {
		CVI_U32 rows = i ? h / 2 : h;
		CVI_U32 l = f->u32Length[i] ? f->u32Length[i] : f->u32Stride[i] * rows;

		va[i] = f->pu8VirAddr[i];
		if (!va[i]) {
			va[i] = CVI_SYS_MmapCache(f->u64PhyAddr[i], l);
			mapped[i] = 1;
			maplen[i] = l;
		}
		if (!va[i]) {
			set_msg("CVI_SYS_MmapCache failed (decoder output plane)");
			goto out;
		}
		CVI_SYS_IonInvalidateCache(f->u64PhyAddr[i], va[i], f->u32Stride[i] * rows);
	}

	for (j = 0; j < h; j++)
		memcpy(dst_y + (size_t)j * w, va[0] + (size_t)j * f->u32Stride[0], w);
	if (!nv12) {
		for (j = 0; j < h / 2; j++) {
			memcpy(dst_u + (size_t)j * (w / 2), va[1] + (size_t)j * f->u32Stride[1], w / 2);
			memcpy(dst_v + (size_t)j * (w / 2), va[2] + (size_t)j * f->u32Stride[2], w / 2);
		}
	} else {
		/* NV12: U,V interleaved; NV21: V,U interleaved */
		int swap = f->enPixelFormat == PIXEL_FORMAT_NV21;

		for (j = 0; j < h / 2; j++) {
			const uint8_t *uv = va[1] + (size_t)j * f->u32Stride[1];
			uint8_t *pu = (swap ? dst_v : dst_u) + (size_t)j * (w / 2);
			uint8_t *pv = (swap ? dst_u : dst_v) + (size_t)j * (w / 2);

			for (i = 0; i < w / 2; i++) {
				pu[i] = uv[2 * i];
				pv[i] = uv[2 * i + 1];
			}
		}
	}
	rc = AAP_CVI_OK;
out:
	for (i = 0; i < 3; i++)
		if (mapped[i] && va[i])
			CVI_SYS_Munmap(va[i], maplen[i]);
	aap_cvi_dec_drop(d);
	return rc;
}
