/*
 * aap_cvi - thin C layer between aa-proxy-rs (Rust) and the Sophgo/Cvitek
 * cvi_mpi libraries (libsys, libvenc, libvdec) of the SG2000/SG2002
 * (Milk-V Duo S).
 *
 * Why C and not hand-written Rust bindings: the MPI structs (VENC_CHN_ATTR_S,
 * VDEC_CHN_ATTR_S, VIDEO_FRAME_INFO_S, ...) are big, nested and full of
 * unions/#ifdefs, so the safest way to get the layout right is to let the C
 * compiler see the vendor headers. This layer exposes a tiny, layout-free API.
 *
 * The flow is the one verified on hardware by milkv-duos-hwcodec-test:
 *   encoder: CVI_VENC_SendFrame   -> CVI_VENC_GetStream   (SEND mode, no bindings)
 *   decoder: CVI_VDEC_SendStream  -> CVI_VDEC_GetFrame    (one access unit per call)
 *
 * All pixel data crossing this API is planar I420 (YUV 4:2:0), tightly packed
 * (stride == width for Y, width/2 for U/V).
 */
#ifndef AAP_CVI_H
#define AAP_CVI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AAP_CVI_OK 0
#define AAP_CVI_AGAIN 1 /* decoder: no frame available (yet) */
#define AAP_CVI_ERR (-1)
#define AAP_CVI_TIMEOUT (-2)

typedef struct aap_cvi_enc aap_cvi_enc;
typedef struct aap_cvi_dec aap_cvi_dec;

/* Human readable description of the last error on the calling thread. */
const char *aap_cvi_last_error(void);

/*
 * Initialise the SYS/VB subsystem (once per process, later calls are no-ops).
 * `max_w` x `max_h` and `blk_cnt` size the common VB pool: every encoder
 * input frame and every decoder output frame is taken from it, so the pool
 * must be big enough for the largest video and for all channels together.
 */
int aap_cvi_sys_init(unsigned max_w, unsigned max_h, unsigned blk_cnt);

/* ------------------------------------------------------------- encoder */

/*
 * `profile`: 0 baseline, 1 main, 2 high. `gop` in frames. `fixed_qp` != 0 selects
 * fixed-QP rate control (constant quality, best for mostly static UI content),
 * otherwise CBR with `bitrate_kbps`.
 * Allocates the lowest free hardware channel.
 */
int aap_cvi_enc_open(aap_cvi_enc **out, unsigned w, unsigned h, unsigned gop, unsigned bitrate_kbps,
		     unsigned fps, unsigned profile, unsigned fixed_qp);
void aap_cvi_enc_close(aap_cvi_enc *e);
int aap_cvi_enc_request_idr(aap_cvi_enc *e);

/*
 * Encode one I420 frame (tightly packed planes). On AAP_CVI_OK `*out`/`*out_len`
 * point to an Annex-B access unit owned by the encoder, valid until the next call.
 * AAP_CVI_TIMEOUT means the frame was accepted but no stream is ready yet; the
 * stream will be returned by a later call (output lags by one frame from then on).
 */
int aap_cvi_enc_encode(aap_cvi_enc *e, const uint8_t *y, const uint8_t *u, const uint8_t *v,
		       int timeout_ms, const uint8_t **out, size_t *out_len);

/* ------------------------------------------------------------- decoder */

/*
 * `w`/`h` are the maximum picture size of the channel (rounded up to the
 * macroblock grid by the caller). `display_frames` is the size of the display
 * queue (0..16, the SDK samples use 2).
 */
int aap_cvi_dec_open(aap_cvi_dec **out, unsigned w, unsigned h, unsigned display_frames);
void aap_cvi_dec_close(aap_cvi_dec *d);

/* Send exactly one access unit (Annex-B, SPS/PPS in-band for the first IDR). */
int aap_cvi_dec_send(aap_cvi_dec *d, const uint8_t *au, size_t len, uint64_t pts, int timeout_ms);

/*
 * Fetch a decoded frame. Two steps so the Rust side can allocate the planes
 * once it knows the size: `get` holds the frame inside the decoder and reports
 * its size, `take` copies it as tightly packed I420 into y/u/v (sizes w*h and
 * (w/2)*(h/2)) and releases it. `get` returns AAP_CVI_AGAIN when no frame is
 * ready (a frame fetched by an earlier `get` stays held); a successful `get`
 * replaces (and releases) a frame that was still held, so the newest wins.
 */
int aap_cvi_dec_get(aap_cvi_dec *d, int timeout_ms, unsigned *w, unsigned *h);
int aap_cvi_dec_take(aap_cvi_dec *d, uint8_t *y, uint8_t *u, uint8_t *v);
/* Drop a frame obtained with `get` without copying it. */
void aap_cvi_dec_drop(aap_cvi_dec *d);

#ifdef __cplusplus
}
#endif

#endif /* AAP_CVI_H */
