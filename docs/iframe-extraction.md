# How I-frame extraction works

Ordinary MP4 demuxers need the `moov` atom. It holds the sample index (where each frame lives)
and the `avcC` box (SPS/PPS — the decoder's recipe for the stream). A truncated download has
usually lost `moov`, so ffmpeg, mpv, and friends cannot decode a single picture even though
most of the video bytes are still sitting in `mdat`.

This tool never reads `moov`, even when one is present. It carves I-frames out of the surviving
bitstream and reconstructs everything a decoder needs from those bytes plus one piece of
information the bitstream cannot recover: the frame size.

Scope: MP4 / H.264 / no audio required / known resolution.

```
file bytes
    │
    ▼
┌─────────────────┐
│ 1. Find mdat    │   ignore ftyp, moov, everything else
└────────┬────────┘
         ▼
┌─────────────────┐
│ 2. Walk NALs    │   follow [4-byte length][payload] until the chain breaks
└────────┬────────┘
         ▼
┌─────────────────┐
│ 3. Recover SPS  │   in-band if present, otherwise synthesise from size + x264 SEI
└────────┬────────┘
         ▼
┌─────────────────┐
│ 4. Group AUs    │   a slice with first_mb == 0 starts a new picture
└────────┬────────┘
         ▼
┌─────────────────┐
│ 5. Decode IDRs  │   feed SPS + PPS + slices to openh264, emit YUV / PNG
└─────────────────┘
```

---

## Why `moov` is ignored on purpose

A truncated file has no `moov`. A file padded with stolen MP4 tail bytes can have a *perfectly
valid* `moov` that describes a completely different video. Trusting it would be worse than not
having it. The carver therefore treats the file as a bag of boxes, takes the first `mdat`, and
stops.

```rust
// MP4 is a sequence of boxes: [size: u32][type: FourCC][payload...]
fn find_mdat(file: &[u8]) -> MdatRange {
    let mut off = 0;
    while off + 8 <= file.len() {
        let size = read_u32_be(&file[off..]);     // declared box size
        let kind = &file[off + 4..off + 8];       // "ftyp", "moov", "mdat", ...

        if kind == b"mdat" {
            // Never trust the declared size. A truncated mdat still advertises
            // its original length, which runs well past EOF.
            return MdatRange {
                start: off + 8,
                end: min(off + size, file.len()),
            };
        }
        off += size; // skip this box, including a perfectly valid moov
    }
    panic!("no mdat");
}
```

Head truncation (missing `ftyp` / `mdat` at the start) is out of scope. Tail truncation is the
case this is built for.

---

## Walking the AVCC chain

H.264 in MP4 is stored in **AVCC** form: each NAL unit is prefixed by its own length, usually
four bytes. That is a self-describing linked list. Starting at the beginning of `mdat` and
following the lengths reconstructs every frame boundary without a sample table. The chain
stops validating exactly where the file was cut.

```
mdat payload
┌──────────┬────────────────┬──────────┬────────────────┬─────┐
│ len = 19 │ SPS NAL bytes  │ len = 4  │ PPS NAL bytes  │ ... │
└──────────┴────────────────┴──────────┴────────────────┴─────┘
     ▲
     walk starts here
```

A length prefix read out of padding will claim to be hundreds of megabytes, or point at a
payload whose first byte is not a legal H.264 header. Several cheap checks reject that:

```rust
fn walk_nals(file: &[u8], mdat: MdatRange, mb_count: u32) -> Vec<Nal> {
    let mut nals = Vec::new();
    let mut pos = mdat.start;

    while pos + 4 <= mdat.end {
        let declared = read_u32_be(&file[pos..]) as usize;
        let payload  = pos + 4;

        // Truncation: the prefix claims more bytes than remain.
        if payload >= mdat.end || declared == 0 {
            break;
        }
        let available = min(declared, mdat.end - payload);
        let header = file[payload]; // first byte of the NAL

        if !plausible_nal(header, declared, &file[payload..payload + available], mb_count) {
            break; // padding, another track, or the cut
        }

        nals.push(Nal {
            offset: pos,
            nal_type: header & 0x1f,          // low 5 bits
            complete: available == declared,  // false iff this unit straddles the cut
            payload: &file[payload..payload + available],
        });

        if available < declared {
            break; // this is the unit the cut landed in
        }
        pos = payload + declared;
    }
    nals
}

fn plausible_nal(header: u8, len: usize, bytes: &[u8], mb_count: u32) -> bool {
    if header & 0x80 != 0 { return false; }           // forbidden_zero_bit must be 0
    let nal_type = header & 0x1f;
    if !matches!(nal_type, 1 | 5 | 6 | 7 | 8 | 9 | 12) { return false; } // x264's set
    if len > mb_count as usize * 3072 { return false; } // no frame is 8× its raw size

    // Slice NALs get a second opinion from their header: a fabricated unit
    // almost never yields a macroblock address inside the picture.
    if matches!(nal_type, 1 | 5) {
        let hdr = parse_slice_header(bytes)?;
        return hdr.first_mb_in_slice < mb_count;
    }
    true
}
```

Interleaved audio (or any other track) sits as a gap in this chain. The walker may scan forward
for the next offset where several consecutive units validate again; if skipping the gap roughly
doubles the NAL count, the file had audio. If it only scrapes a handful of extra units out of
padding, the gap is the truncation point and those units are discarded.

A picture is only trusted once the chain has moved on to the *next* picture. Without that rule
a multi-slice IDR whose last slice fell past the cut looks whole, because every surviving slice
is individually well formed.

---

## Recovering SPS / PPS

A decoder cannot parse a slice without parameter sets. They normally live in `avcC` inside
`moov`. Two recovery paths:

1. **In-band.** Some encoders repeat SPS (type 7) and PPS (type 8) in the bitstream. If both
   survive complete, use them as-is.
2. **Synthesise.** Otherwise build them from `--size` plus x264's options SEI.

x264 writes its full option string as the first SEI NAL of the file, so it survives any tail
cut:

```
cabac=1 ref=3 8x8dct=1 chroma_qp_offset=-2 bframes=3 keyint=48 rc=crf crf=23.0 ...
```

That string pins almost every SPS/PPS field. Resolution cannot be recovered from it (it lives
in the lost SPS), which is why `--size` is required. Colour matrix lives in the SPS VUI for
the same reason, so PNG output needs `--matrix` as a guess (BT.709 for HD).

```rust
fn recover_parameter_sets(nals: &[Nal], width: u32, height: u32) -> ParameterSets {
    // Path 1: the encoder repeated them in-band.
    if let (Some(sps), Some(pps)) = (find_complete(nals, SPS), find_complete(nals, PPS)) {
        return ParameterSets { sps, pps, source: InBand };
    }

    // Path 2: parse x264's option SEI (always the first NAL on an x264 file).
    let opts = nals.iter()
        .find(|n| n.nal_type == SEI)
        .and_then(|n| parse_x264_sei(n.payload))
        .unwrap_or_default(); // typical High / CABAC if the SEI is missing

    // pic_init_qp is the one field the SEI cannot pin down.
    // Plain CRF often matches round(crf); --stitchable and ABR leave x264's default of 26.
    // CABAC context init depends on SliceQPY, so a wrong guess fails the decode loudly.
    for qp in qp_search_order(&opts) {          // try round(crf), then 26, then 0..=51
        let params = synthesize_sps_pps(width, height, &opts, qp);
        if decode_first_idr(&params, nals).is_ok() {
            return params;                      // first candidate that actually decodes
        }
    }
    panic!("no parameter sets decoded the first intra frame");
}
```

Synthesis follows x264's header writer, not a snapshot of one file:

| field | rule |
|---|---|
| profile | High if `8x8dct`, else Baseline if CAVLC and no B-frames, else Main |
| `log2_max_frame_num` | always 4 |
| `pic_order_cnt_type` | 0 (lsb 6) with B-frames, 2 without |
| DPB size | x264's `max(ref, 1+reorder, pyramid ? 4 : 1)` |
| scaling matrices | never present |
| `gaps_in_frame_num_value_allowed` | always 0 |

If the SEI-derived knobs fail, a short fallback flips entropy coding, 8×8 transform, and
B-frames (POC type) so a missing or non-x264 SEI is not fatal. It will not invent a scaling
matrix or an interlaced SPS.

```rust
fn synthesize_sps_pps(w: u32, h: u32, opts: &X264Options, qp: i32) -> ParameterSets {
    let mb_w = w.div_ceil(16);
    let mb_h = h.div_ceil(16);

    // SPS — just enough for a progressive 4:2:0 IDR.
    let mut sps = BitWriter::new();
    sps.u(8, 0x67);                    // nal_ref_idc=3, type=7
    sps.u(8, profile_for(opts));
    sps.ue(0);                         // log2_max_frame_num_minus4 → 4
    sps.ue(if opts.bframes > 0 { 0 } else { 2 }); // POC type
    sps.ue(mb_w - 1);
    sps.ue(mb_h - 1);
    sps.flag(true);                    // frame_mbs_only
    // crop the 16-aligned coded size back to the real width/height
    write_cropping(&mut sps, w, h);

    // PPS
    let mut pps = BitWriter::new();
    pps.u(8, 0x68);                    // nal_ref_idc=3, type=8
    pps.flag(opts.cabac);
    pps.se(qp - 26);                   // pic_init_qp_minus26 — the searched field
    pps.flag(opts.transform_8x8);

    ParameterSets { sps: sps.finish(), pps: pps.finish(), source: Synthesized }
}
```

---

## Grouping access units

An access unit is one picture: every VCL NAL (slice or IDR) that belongs to it. Multi-slice
encodes split a picture across several NALs. The H.264 rule is simple and does not need
access-unit delimiters:

> A VCL NAL with `first_mb_in_slice == 0` starts a new picture.

Those two fields are the first `ue(v)` values in the slice header, so they can be read
*before* any parameter set has been recovered.

```rust
fn group_access_units(nals: &[Nal]) -> Vec<AccessUnit> {
    let mut pictures = Vec::new();

    for (i, nal) in nals.iter().enumerate() {
        if nal.nal_type != SLICE && nal.nal_type != IDR { continue; }
        let header = parse_slice_header(nal.payload)?;

        if header.first_mb_in_slice == 0 || pictures.is_empty() {
            pictures.push(AccessUnit {
                nals: vec![i],
                is_idr: nal.nal_type == IDR,
                is_intra: header.slice_type % 5 == 2, // I-slice
                complete: nal.complete,
            });
        } else {
            // continuation slice of the current picture
            let pic = pictures.last_mut().unwrap();
            pic.nals.push(i);
            pic.complete &= nal.complete;
        }
    }

    // If the chain did not run cleanly to EOF, the last picture is the one
    // the cut landed in — even when every surviving slice looks fine.
    if chain_broke {
        pictures.last_mut().complete = false;
    }
    pictures
}

fn parse_slice_header(nal: &[u8]) -> Option<SliceHeader> {
    // Skip the 1-byte NAL header, undo emulation-prevention (0x000003 → 0x0000),
    // then read the first two Exp-Golomb fields. The rest of the header needs SPS.
    let rbsp = unescape(&nal[1..nal.len().min(32)]);
    Some(SliceHeader {
        first_mb_in_slice: read_ue(&rbsp)?,
        slice_type:         read_ue(&rbsp)?,
    })
}
```

By default only complete IDRs are decoded. `--include-non-idr` also keeps intra slices that
are not IDR (x264 with `open_gop=0` does not emit these). `--include-partial` attempts the
frame straddling the cut; see limits below.

---

## Decoding

openh264 sits behind a `FrameDecoder` trait so a hand-written intra decoder can be swapped in
later without touching the carver. Each wanted picture is packaged as Annex B (start-code
prefixed) with the recovered SPS/PPS prepended, then handed to the decoder as one access unit.

```rust
fn decode_iframes(nals: &[Nal], pictures: &[AccessUnit], params: &ParameterSets) -> Vec<Frame> {
    let mut decoder = OpenH264::new();
    let mut frames = Vec::new();

    for pic in pictures.iter().filter(|p| p.is_idr && p.complete) {
        // Annex B: 00 00 00 01 <nal>  00 00 00 01 <nal> ...
        let mut au = annexb(&[&params.sps, &params.pps]);
        for &i in &pic.nals {
            au.extend(annexb(&[nals[i].payload]));
        }

        match decoder.decode_au(&au) {
            Ok(Some(yuv)) => frames.push(yuv),
            Ok(None)      => { /* decoder accepted the bytes but emitted no picture */ }
            Err(_)        => {
                // A poisoned decoder would take every later frame with it.
                // The picture on the cut is expected to fail; reset and continue.
                decoder = OpenH264::new();
            }
        }
    }
    frames
}

fn annexb(nals: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for n in nals {
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(n);
    }
    out
}
```

Decoded output is planar 4:2:0 YUV. PNG is a colour-converted preview; the YUV→RGB matrix
cannot be recovered (it lived in the lost SPS VUI), so it is supplied as `--matrix`.
Comparison against a reference decoder is done on YUV, where two conformant decoders are
bit-exact. PNG will differ by under one LSB per channel from ffmpeg's PNGs — that gap is
entirely the YUV→RGB step.

There are no timestamps. The timescale lives in `moov` and the frame rate in the SPS VUI,
both gone. Files are named by byte offset, which is stable and joins against a packet index:

```
frame_00007_off_0000151793.png
```

---

## What the GUI does with this

The GUI is a thin wrapper around the same pipeline. The user supplies the file and the
resolution (prefilled from the analyzer when `moov` happens to be intact). Extraction runs
on a background thread; each decoded YUV frame is converted to RGB, thumbnailed, and encoded
as PNG for the grid.

```rust
fn run_extract(path: &Path, width: u32, height: u32) -> Extracted {
    let bytes = std::fs::read(path)?;
    let result = iframe_extract::extract(&bytes, path, Options { width, height, .. })?;

    for (record, yuv_frame) in result.frames {
        let rgb = yuv_frame.to_rgb(ColorMatrix::Bt709);
        save_png(&rgb, record.offset);
    }
}
```

The analyzer and the extractor are complementary: the analyzer reads `moov` when it exists
and tells you the layout is incomplete when it does not; the extractor is the path that
still produces pictures after that.

---

## Limits

- **Head truncation is out of scope.** The file must still start with `ftyp`/`mdat`, and the
  x264 SEI must still be the first NAL.
- **`--size` is required**, and `--matrix` is a guess. Both lived in structures the cut
  destroyed.
- **No timestamps**, for the same reason.
- **Partial frames are reported, not invented.** When the cut lands inside an IDR the JSON
  records `partial: true, decoded: false` and no image is written. openh264 will not emit a
  picture for a slice-incomplete IDR. Salvaging the macroblock rows that did arrive needs a
  decoder that can emit a partial picture — the planned second backend.
- **The calibration table is x264-specific.** Other encoders fall back to searching entropy
  coding, transform, POC type, and every `pic_init_qp`. That covers typical High/Main/Baseline
  IDRs; it will not invent a scaling matrix or interlaced SPS.
