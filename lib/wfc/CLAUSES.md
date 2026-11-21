# lib/wfc: functions, states and clauses

This file is the table the crate is built and tested against. "Spec" is the
section of the OpenWF Composition 1.0 specification (5 November 2009). "Plan"
is the design plan of graphics step G7 (P3.1 is its section 3.1, P5.4 its
section 5.4, and so on). "S0" is the clause table of the specification check of G7 (its section 5 rows
are called R-activity, R-transparency, R-mask, R-limits, R-blend). The text of
the specification (chapters 2 to 8 and 10) and the headers `wfc.h` and
`wfcplatform.h` were read in full for this table.

## 1. Shape of the crate

* `Wfc` is one device. It owns every pending state: the context, the
  elements, the sources, the masks, the order of the scene, the last
  committed scene, the last error. No setter or getter makes a system call.
* Calls that reach the service (`commit`, `activate`, `deactivate`,
  `compose`, and `destroy_context` of an active context) take a
  `&mut impl Service`. `Service` has these methods, each returning
  `Result<(), Status>` with `proto_wire::Status` (the claims return `bool`):
  `scene_commit(&SceneCommit)`, `scene_compose(flags)`, `wait(bit)` (block
  until the bit of the scene's channel is set), `clear(bit)` (forget a bit that
  is set), `pause()` (block until the service may have moved on, at most one
  frame) and `claim_screen()` and `release_screen()` (one context per screen
  for the whole service session, spec 5.2). The host tests use a fake service
  that records the messages and plays back chosen refusals.
* Several devices may exist (spec 4.3: devices of one id are supported, each
  with its own state). Each `Wfc` is a device. Handles come from one process-wide
  atomic counter, so a handle of another device is simply unknown to this one
  and is BAD_HANDLE. The second device's context on the taken screen is IN_USE
  because the claim is the service's.
* Thread safety (spec 2.13) is the C layer's: it holds one lock around every
  call that takes a `Wfc` and its `Service`. Without it another thread could
  take the bit a `wait` is for.
* Calls that need the size and format of a stream (`create_source_from_stream`,
  `create_mask_from_stream`) take the answer of the layer above as an
  `Option<StreamInfo>` (width, height, format of the window; `None` is a
  window that does not exist). The layer above looks it up from LIST. The
  library keeps the size from creation on (spec 2.8.1: the dimensions and the
  format of a stream never change), so commit needs no lookup.
* Handles are `u32`, 0 is `WFC_INVALID_HANDLE`, and handles of distinct
  objects differ (spec 2.6), also across devices.
* Numbers of `<WF/wfc.h>` are in `consts`, under the header's names without
  the prefix `WFC_`.
* Public pure functions (the host reference shares them): `to_fixed(f32) ->
  i32` (16.16, round to nearest, saturating), `to_alpha(f32) -> u32` (0 to
  255, round to nearest, clamped), `rect_to_fixed([f32; 4]) -> [i32; 4]`,
  `fold(rotation, flip, ctx_rotation) -> (rotation, mirror)` and
  `fold_rect(rect, ctx_rotation, target) -> rect`. The crate depends on
  `proto-comp`, `proto-wire` and `abi`.

## 2. State

| State | Holds | Default | Spec |
|---|---|---|---|
| device | handle, last error (the oldest since the last `get_error`), `lost` flag | no error, service present | 2.11, 4 |
| context (at most 1) | handle, screen, rotation, background as `[f32; 4]`, `active`, `committed: SceneCommit` (last scene the service accepted), `compose_pending` | rotation 0, background (0,0,0,1), inactive, committed = empty scene with opaque black | 5.1, 5.4, 8 |
| target size | width and height from `Setup` (640 by 400 on virtio-gpu); rotation leaves them as they are | from `Setup` | 5.1.2, 5.1.4 |
| element (up to 16) | handle, destination rectangle `[i32; 4]`, source handle, source rectangle `[f32; 4]`, flip, rotation, filter, transparency bits, global alpha `f32`, mask handle, "in scene" | (0,0,0,0), none, (0,0,0,0), false, 0, NONE, 0, 1.0, none, outside the scene | 7.1 table 4 |
| scene order | element handles, bottom first, at most 16 | empty | 7.5 |
| source (up to 8) | handle, window id, width, height, format, `alive` | | 6.1 |
| mask (up to 8) | handle, window id, width, height, `alive` | | 6.2 |

A destroyed source or mask stays in its slot while an element refers to it
(spec 6.1.2, 6.2.2: it exists until it is detached or the element is
destroyed); its handle is no longer valid for any call. The slot counts
against the limit until it is freed.

## 3. Functions

Every function first checks the device: a handle that is no device has no
effect and stores no error (spec 2.11); `get_error` of it returns
BAD_DEVICE. Then the other handles (BAD_HANDLE), then the attribute
(BAD_ATTRIBUTE for an unknown attribute, a read-only one in a setter, an
accessor the attribute does not allow), then the count and pointer
(ILLEGAL_ARGUMENT for a count that differs from the attribute's size and for
a missing buffer), then the value (ILLEGAL_ARGUMENT). A failing function
changes nothing (spec 2.11, 5.6, 7.4).

### 3.1 Device

| Function | State | Errors and results | Spec | Row |
|---|---|---|---|---|
| `wfcEnumerateDevices` | none | the filter list is pairs ending with NONE; an attribute other than SCREEN_NUMBER, a value other than 0 (`WFC_DEFAULT_SCREEN_NUMBER`), a repeated SCREEN_NUMBER: empty list, 0; null buffer returns the count (1); negative count writes nothing and returns 0 | 4.2, 4.2.1 | P3.1 |
| `wfcCreateDevice` | creates a device | id 0 or 1; another id, or a non-empty attribute list: handle 0, no error stored (no device yet). Creating it again gives a second device with its own state | 4.3 | P3.1 |
| `wfcGetError` | reads and clears the error | invalid device: BAD_DEVICE; else the oldest error since the last call, then NONE | 2.11 | P5.4 |
| `wfcGetDeviceAttribi` | none | CLASS gives FULLY_CAPABLE, ID gives 1; another attribute: BAD_ATTRIBUTE | 4.1, 4.4 | P3.1 |
| `wfcDestroyDevice` | drops all state | invalid device: BAD_DEVICE; else NONE; every handle becomes invalid; the context is closed as `wfcDestroyContext` does (see 3.2) | 4.5 | P3.1 |
| `wfcGetStrings` | none | invalid device: 0, buffer untouched; name not VENDOR, RENDERER, VERSION, EXTENSIONS, or negative count: ILLEGAL_ARGUMENT, 0; "stafeto", "stafeto-compositor", "1.0", one extension `WFC_STAFETO_stream` (its function is `wfcNextStreamSTAFETO`, named by spec 10.1) | 10.1, 10.3.2 | P3.1, P5.2 |
| `wfcIsExtensionSupported` | none | TRUE for `WFC_STAFETO_stream` only; invalid device FALSE | 10.3.2 | P5.2 |

### 3.2 Context

| Function | State | Errors and results | Spec | Row |
|---|---|---|---|---|
| `wfcCreateOnScreenContext` | creates the context | screen 0 (the default) only, else UNSUPPORTED; the screen already claimed (by this device or another): IN_USE; non-empty attribute list: BAD_ATTRIBUTE; the creation result on error is 0 | 5.2 | P3.1, R-limits |
| `wfcCreateOffScreenContext` | none | UNSUPPORTED (no off-screen target in this release), result 0; see decision 10 | 5.3 | P3.2 |
| `wfcDestroyContext` | drops the context, its elements, sources, masks and order, and releases the screen | BAD_HANDLE; the pending composition completes first (`wait(COMPOSED)` when `compose_pending`); an active context is deactivated through the service; the committed scene stays on the screen (spec 8.2, footnote 15). Limit: the service answers the deactivation at once and finishes a frame in progress by itself, so the call does not wait for that frame. On a lost device the state is dropped with no message and no error | 5.7, 4.5 | P3.1 |
| `wfcGetContextAttribi` | none | TYPE gives ON_SCREEN, TARGET_WIDTH, TARGET_HEIGHT, LOWEST_ELEMENT (the bottom handle of the pending order, 0 for an empty scene), ROTATION (the enum), BG_COLOR (packed 0xRRGGBBAA, each channel `to_alpha`); BAD_HANDLE; BAD_ATTRIBUTE for others | 5.1, 5.5 | P3.1 |
| `wfcGetContextAttribfv` | none | only BG_COLOR allows it: count 4, else ILLEGAL_ARGUMENT; the others: BAD_ATTRIBUTE; null buffer ILLEGAL_ARGUMENT; the values come back exactly as set (spec 2.12) | 5.5 | P3.1 |
| `wfcSetContextAttribi` | pending rotation or background | TYPE, TARGET_*, LOWEST_ELEMENT read-only: BAD_ATTRIBUTE; ROTATION must be one of the four enums, else ILLEGAL_ARGUMENT; BG_COLOR is 0xRRGGBBAA, each channel over 255, alpha must be 255 for an on-screen context, else ILLEGAL_ARGUMENT | 5.1.4, 5.1.5, 5.6 | P3.1 |
| `wfcSetContextAttribfv` | pending background | only BG_COLOR: count 4; each value in [0,1] and finite, alpha exactly 1, else ILLEGAL_ARGUMENT; null ILLEGAL_ARGUMENT; ROTATION by this accessor BAD_ATTRIBUTE | 5.1.5, 5.6 | P3.1 |
| `wfcCommit` | see 4.1 | BAD_HANDLE; INCONSISTENCY; service refusals translated; with `wait` the bit COMMITTED | 5.4 | P5.4, P5.3, R-mask |

### 3.3 Sources and masks

| Function | State | Errors and results | Spec | Row |
|---|---|---|---|---|
| `wfcCreateSourceFromStream` | new source | BAD_HANDLE (context); non-empty attribute list BAD_ATTRIBUTE; stream `None` (no such window): ILLEGAL_ARGUMENT; format A8: UNSUPPORTED (an A8 window is a mask only); 8 live or pending-release sources: OUT_OF_MEMORY; a lost device: BAD_DEVICE; result 0 on error. BUSY and IN_USE cannot arise (no off-screen target, no other context) | 6.1.1 | P3.1, P3.2, R-limits |
| `wfcDestroySource` | marks dead | BAD_HANDLE; slot freed when no element refers to it | 6.1.2 | P3.1 |
| `wfcCreateMaskFromStream` | new mask | as above; format other than A8: UNSUPPORTED | 6.2.1 | P3.1, P5.2 |
| `wfcDestroyMask` | marks dead | BAD_HANDLE | 6.2.2 | P3.1 |

### 3.4 Elements

| Function | State | Errors and results | Spec | Row |
|---|---|---|---|---|
| `wfcCreateElement` | new element with the defaults, outside the scene | BAD_HANDLE (context); non-empty attribute list BAD_ATTRIBUTE; the 17th element: OUT_OF_MEMORY (the 16 that fit one SCENE_COMMIT are also the most that exist, so an insert never overflows); result 0 | 7.2 | P3.1, R-limits |
| `wfcGetElementAttribi` | none | allowed for SOURCE, FLIP, ROTATION, SCALE_FILTER, TRANSPARENCY_TYPES, GLOBAL_ALPHA (round(255 x)), MASK; DESTINATION_RECTANGLE and SOURCE_RECTANGLE give BAD_ATTRIBUTE | 7.3, 7.1 | P3.1 |
| `wfcGetElementAttribf` | none | only GLOBAL_ALPHA | 7.1.8 | P3.1 |
| `wfcGetElementAttribiv` | none | DESTINATION_RECTANGLE (4 ints), SOURCE_RECTANGLE (4 floats, floor of each, as spec 2.12 says for a mismatched variant) | 7.1.1, 7.1.3 | P3.1 |
| `wfcGetElementAttribfv` | none | the same two; a source rectangle set by `fv` comes back unchanged | 2.12 | P3.1 |
| `wfcSetElementAttribi` | pending attribute | SOURCE (a live source, or 0; a handle that is none of these: ILLEGAL_ARGUMENT, see 6), FLIP (any non-zero is TRUE, spec 2.3 WFCboolean), ROTATION and SCALE_FILTER (the listed enums, else ILLEGAL_ARGUMENT), TRANSPARENCY_TYPES (none, each single bit, the two pairs of 7.1.7; every other pattern ILLEGAL_ARGUMENT), GLOBAL_ALPHA (0 to 255, over 255.0), MASK (a live mask or 0) | 7.4, 7.1 | P3.1, R-transparency |
| `wfcSetElementAttribf` | pending attribute | only GLOBAL_ALPHA, in [0,1], else ILLEGAL_ARGUMENT | 7.1.8 | P3.1 |
| `wfcSetElementAttribiv` | pending rectangle | DESTINATION_RECTANGLE: count 4, width and height not negative, magnitudes within 16,777,216 (`COORD_MAX`); SOURCE_RECTANGLE: the ints convert exactly, no value negative | 7.1.1, 7.1.3 | P3.1 |
| `wfcSetElementAttribfv` | pending rectangle | destination: each float floored (spec 2.12), then as above; source: no value negative, none above 16,777,216, none NaN | 7.1.1, 7.1.3 | P3.1 |
| `wfcInsertElement(dev, element, subordinate)` | moves the element in the order: immediately above `subordinate`; `subordinate` 0 puts it at the bottom | BAD_HANDLE for an invalid element or a non-zero invalid `subordinate`; ILLEGAL_ARGUMENT when `subordinate` is outside the scene (this includes `subordinate == element` for an element outside it); `subordinate == element` inside the scene: no effect. With one context the "different context" case reaches only elements of a destroyed context, which are BAD_HANDLE | 7.5.1 | P5.4 |
| `wfcRemoveElement` | leaves the order | BAD_HANDLE; outside the scene: no effect | 7.5.2 | P5.4 |
| `wfcGetElementAbove` | none | BAD_HANDLE; outside the scene: ILLEGAL_ARGUMENT, result 0; top-most: 0 | 7.5.3 | P5.4 |
| `wfcGetElementBelow` | none | as above for the bottom | 7.5.3 | P5.4 |
| `wfcDestroyElement` | drops the element, leaves the order, releases its source and mask | BAD_HANDLE; the committed scene is unchanged until commit | 7.6 | P3.1 |

### 3.5 Rendering

| Function | State | Errors and results | Spec | Row |
|---|---|---|---|---|
| `wfcActivate` | `active` | BAD_HANDLE; already active: no effect and no message; else one SCENE_COMMIT of the last committed scene with ACTIVE; success sets `active`. It does not wait for a commit and does not read the pending state | 8.1 | P5.4, R-activity |
| `wfcDeactivate` | `active` | BAD_HANDLE; already inactive: no effect; else the same scene without ACTIVE | 8.2 | P5.4, R-activity |
| `wfcCompose` | `compose_pending` | BAD_HANDLE; active context: UNSUPPORTED (checked here, and also the service's answer is translated); else SCENE_COMPOSE with COMPOSED asked; BUSY when `wait` is false and the service says so; with `wait` see 4.3 | 8.3 | P5.3, P5.4, R-activity |
| `wfcFence` | none | BAD_HANDLE; then ILLEGAL_ARGUMENT: spec 9 lists no UNSUPPORTED, and with no EGL there is no valid display or sync object to pass | 9 | P3.2 |

The service's LIST gives a window's size and no format, so the C binding passes
`FORMAT_UNKNOWN` as the format of a stream; creation then accepts the stream for
a source or a mask, and the service checks the kind of the window at the commit
(an INVALID there comes back as ILLEGAL_ARGUMENT). A flag for the format A8 in
LIST's `flags` would let creation answer UNSUPPORTED as 6.1.1 and 6.2.1 say.

## 4. Commit and the translation of refusals

### 4.1 What `commit` does, in order

1. BAD_HANDLE for the context. A lost device (see 4.2) stores BAD_DEVICE and stops.
2. Consistency, over the elements in the scene (an element outside the scene
   takes no part in composition, spec 7.5): a source rectangle not fully inside
   its source (`sx + sw <= width`, `sy + sh <= height`, float arithmetic as the
   specification says in footnote 13) and a mask whose size differs from the
   destination rectangle (spec 7.1.9; the mask is not stretched, R-mask) give
   INCONSISTENCY and send nothing. The mask is checked whenever it is set. A
   transparency pattern outside the allowed list never reaches commit because
   the setter refused it (R-transparency).
3. Build the record, bottom up, one `proto_comp::Element` per element of the
   scene that draws something (the order is: the float consistency check of
   step 2, then the rounding, then the trim, then the dropping). An element is
   left out when its destination rectangle or its source rectangle (in 16.16
   after the trim) has a zero side or when it has no source
   (spec 7.1.1, 7.1.2, 7.1.3: such an element does not affect the result;
   the service refuses a zero source side). A zero global alpha with the alpha
   bit stays in the record and the service draws nothing for it.
   * `source`: the window id, `mask`: the window id of the mask when the MASK bit is on and a mask
     is set, else `NO_WINDOW`. A MASK bit with no mask set is cleared in the record (spec 7.1.9: no masking
     is the same as a mask of ones).
   * source rectangle: `rect_to_fixed`; then the width and height are
     trimmed to the window's edge in 16.16 (floor 0), so a rectangle that the
     float check accepted is also inside in 16.16; only then the element is
     dropped if a side is zero in 16.16 (`sw` of 1e-6 rounds to 0, and the
     trim can bring a side to 0).
   * `orient` and the destination: the context rotation is folded in (see 5).
   * `filter`: NONE and FASTER give NEAREST, BETTER gives BILINEAR.
   * `transparency`: the bits as they are (the record uses the `WFC_TRANSPARENCY_*` bits);
     `alpha`: `to_alpha(global alpha)`.
   * `bg`: the context colour, each channel `to_alpha`, premultiplied by the alpha (always 255 on-screen).
   * `flags`: ACTIVE if the context is active, ASK_COMMITTED if `wait`.
4. With `wait`, `Service::clear(COMMITTED_BIT)` first, then `Service::scene_commit`
   (a BUSY answer with `wait` is waited out as in 4.3). On success the record (without ASK_COMMITTED)
   becomes `committed`; on refusal it stays as it was and the pending state is
   untouched.
5. With `wait`, `Service::wait(COMMITTED_BIT)`.

The service can answer BUSY to SCENE_COMMIT as it can to SCENE_COMPOSE (for
instance while another holder has the scene). With `wait` false the BUSY is the
result, as spec 5.4 allows ("if `wait` is WFC_FALSE and ctx is not ready"); with
`wait` true it is waited out as in 4.3. Waiting for COMMITTED under `wait` is
stricter than the specification asks (5.4 says completion means the context
accepts a new commit); it is the one bit the service gives.

### 4.2 Refusals

| Service answer | Error stored |
|---|---|
| kernel LIMIT_REACHED, NO_MEMORY | WFC_ERROR_OUT_OF_MEMORY |
| NOT_ALLOWED | WFC_ERROR_ILLEGAL_ARGUMENT |
| BUSY | WFC_ERROR_BUSY |
| UNSUPPORTED | WFC_ERROR_UNSUPPORTED |
| kernel PEER_CLOSED, BAD_HANDLE, and the service codes NO_DEVICE, REVOKED | WFC_ERROR_BAD_DEVICE, and the device is `lost` |
| INVALID, BAD_SIZE, BAD_VERSION, UNKNOWN_METHOD, anything else | WFC_ERROR_ILLEGAL_ARGUMENT for INVALID and BAD_SIZE; BAD_DEVICE for BAD_VERSION and UNKNOWN_METHOD; see question 3 in section 6 |

A lost device answers BAD_DEVICE from every function that would call the
service (`commit`, `activate`, `deactivate`, `compose`), from
`create_source_from_stream`, `create_mask_from_stream` and from the check the
extension `wfcNextStreamSTAFETO` makes (`Wfc::stream_allowed`), without
calling the service. Plain setters and getters keep working on the cached
state. `destroy_context` and `destroy_device` on a lost device drop the state
silently.

Finding on window ids (checked in `services/compositor`): an id is the place
and a generation that grows (`window_id`, `ID_GENERATION_MAX`), so the id of a
window that went is never another window's, and a window keeps its size. An
INVALID from SCENE_COMMIT after the library's own checks therefore cannot be a
stale id naming a window of another size; it is a bug of the library and stays
ILLEGAL_ARGUMENT (it is not mapped to INCONSISTENCY).

### 4.3 Waiting

Both requests go through one routine. Before every send of `compose` the
library calls `clear(COMPOSED)` (and before every send of `commit` with `wait`,
`clear(COMMITTED)`), whatever `wait` is, and it never clears after the service
has accepted: the service may set the bit of the new frame before its answer, so
a clear afterwards could erase it and a later wait would never end. A stale bit
of an earlier frame therefore never counts for this one.

* With `wait` true: on BUSY the library calls `pause()` (at most a frame) and
  sends again, so the call does not fail with BUSY (spec 5.4, 8.3). After the
  service accepts, `wait(bit)`.
* The tries are bounded: at most 16 sends (16 frames). A service that has not
  taken the request by then is not usable; spec 8.3 forbids BUSY with `wait`, so
  the call stores WFC_ERROR_BAD_DEVICE (the device is not marked lost, a later
  call may succeed). Without `wait` the first BUSY is the result.
* A transient refusal (kernel Interrupted or WouldBlock) says nothing about the
  service: it is sent again within the same bound, never marks the device lost,
  and stores WFC_ERROR_BUSY if the bound runs out. `wait` and `pause` are called
  again the same way.
* `compose_pending` is set when a compose was accepted and cleared when its wait
  returned. A refusal of a later `compose` other than BUSY clears it too (the
  clearing before the send may have erased the bit of an earlier frame that is
  over), so `destroy_context` and `destroy_device` never wait for a bit that
  cannot come. They call `wait(COMPOSED)` while it is set.

The `Service` contract: `wait` and `pause` return `Err` (PEER_CLOSED) when the
channel closes, so no wait outlives the service. The handle counter stops at
`u32::MAX` (never wrapping to 0, which is WFC_INVALID_HANDLE): creating past it
stores WFC_ERROR_OUT_OF_MEMORY. The public pure functions `fold` and `fold_rect`
accept any input (`fold` reduces modulo 4, `fold_rect` wraps).
`create_on_screen_context` checks the lost flag before it claims the screen.

## 5. Context rotation folded into an element

Spec 3 puts the flip (top to bottom, about the horizontal centreline) before
the rotation (clockwise) and the context rotation (clockwise) after both. The
record's `orient` is a rotation by quarter turns clockwise, then a reflection
about the vertical axis. With element rotation `r`, context rotation `c`
(quarter turns) and the flip `f`:

* no flip: rotation `(r + c) mod 4`, no reflection;
* flip: rotation `(2 - r - c) mod 4`, reflection on (a vertical flip is a half turn and a reflection about the vertical axis).

The destination rectangle `(x, y, w, h)` in context coordinates becomes, for a
target of `W` by `H`: 0: `(x, y, w, h)`; 90: `(W - y - h, x, h, w)`; 180: `(W - x - w, H - y - h,
w, h)`; 270: `(y, H - x - w, h, w)`. For 90 and 270 the context view is `H`
wide and `W` high (the reported target size does not change, spec 5.1.4, and
the view turns with the rotation). The tests check the folded element
against an independent point-by-point reference built straight from spec 3
(`proto_comp::meaning` is the service's reference of the record; the fold is
the library's step from the API's attributes to that record).

The specification contradicts itself on the flip. The introduction of chapter
7 says flipping is "performed about the vertical axis running through the
centre of the source rectangle"; stage 3 of section 3 and section 7.1.4 say
the image is inverted "top-to-bottom about the horizontal centerline", and the
Khronos sample implementation flips vertically. The table follows stage 3 and
7.1.4 (top to bottom, before the rotation). Check from the review: element
rotation 0, context rotation 90, flip on: source point (1,0) of a 2 by 2
source goes to (0,1) and (0,0) stays at (0,0); the wrong formula with
`q = r + c + 2` gives (1,0) at (1,0), so the test tells them apart.

## 6. Decisions that are mine and need a word from the review

1. **Transparency pattern refused at the setter.** The specification allows
   only NONE, each single bit and two pairs. R-transparency says "refusal at
   the setter, inconsistent at commit". I refuse with ILLEGAL_ARGUMENT at the
   setter (spec 7.4: invalid value of a valid attribute), so commit can only meet an allowed pattern.
2. **BAD_DEVICE after the loss of the service.** I read "from any function"
   as: every function that talks to the service, plus `get_error` returning
   the stored code. Setters and getters of cached state keep their normal
   results because the specification has them answer from the cache (5.4).
3. **Other service codes.** INVALID and BAD_SIZE (a message the library built
   badly) give ILLEGAL_ARGUMENT; protocol mismatch (BAD_VERSION,
   UNKNOWN_METHOD) gives BAD_DEVICE. Neither is listed in P5.4.
4. **Limits.** 16 elements created (inserted or not), 8 sources and 8 masks.
   P3.1 gives 16 elements in the scene and 8 streams.
5. **One context per screen.** A second context on the screen, from this
   device or another, is IN_USE (spec 5.2). The test "insert with a
   subordinate from another context" of P8.1 uses the element of a second
   device (BAD_HANDLE) and of a destroyed context.
6. **SOURCE and MASK values.** A handle that is not a live source (a mask
   handle, a destroyed one, junk) is ILLEGAL_ARGUMENT, because 7.4 gives BAD_HANDLE only for the element.
7. **Screens.** Only 0 (`WFC_DEFAULT_SCREEN_NUMBER`) names the screen.
8. **Consistency checks run on the elements in the scene** (spec 7.1.3,
   7.1.9 and 7.5: the scene is the ordered list used for rendering; an element
   outside it has no effect).
9. **Destroying an active context** sends a deactivation first, so the
   service stops composing for it; the last image stays on the screen.
10. **Off-screen context and fence.** Departure: section 4.1.1 says a
    fully-capable device can render off-screen and chapter 5 requires several
    off-screen contexts. The device reports FULLY_CAPABLE but
    `wfcCreateOffScreenContext` answers UNSUPPORTED (no stream as a target
    until G8). `wfcFence` answers ILLEGAL_ARGUMENT (see 3.5). Both live in the
    library so the C layer has one place for them.
11. **Zero-size elements** are left out of the record (the service refuses a zero source side).

## 7. Tests (170, grouped by clause)

Every test carries its clause in its name or its first comment.

| Group | Clause | Count |
|---|---|---|
| device: enumeration filters (empty, screen 0 and 1, bad value, bad attribute, repeated, null buffer, negative count), create (ids 0, 1, other, attribute list), class and id, bad attribute, destroy, strings and extensions | 4.1 to 4.5, 10.3.2 | 14 |
| error state: starts NONE, oldest kept, cleared by the read, invalid device gives BAD_DEVICE and stores nothing, setters on an invalid device do nothing | 2.11 | 6 |
| device: second device, its context IN_USE, handles of one device on the other BAD_HANDLE | 4.3, 5.2 | 4 |
| context: create (screens, second one IN_USE, attributes), off-screen UNSUPPORTED, defaults, read-only attributes, rotation values, background by `i` and `fv` (range, alpha 1, round trip), target size, lowest element, destroy invalidates elements, sources and masks | 5.1 to 5.7 | 14 |
| sources and masks: creation (no stream, wrong format, limit), destroy while attached, destroy frees the slot after the element goes, wrong-kind handle | 6.1, 6.2 | 8 |
| elements: defaults of all nine attributes, accessor matrix (BAD_ATTRIBUTE), count and null, rectangle limits, negative sizes, floor conversion, the float round trip, alpha `i` and `f` forms, filter, flip, rotation, transparency patterns (all 8), limit of 16 | 7.1 to 7.4 | 16 |
| ordering: insert at the bottom, above, re-insert, onto itself, outside-scene subordinate, above and below, remove, destroy removes, lowest element follows | 7.5, 7.6 | 9 |
| commit: record order bottom up, empty elements left out, source rectangle in 16.16, the clamp at the edge, a zero side after rounding, mask size mismatch INCONSISTENCY, source outside INCONSISTENCY sends nothing, mask bit cleared without a mask, filter map, alpha, background, wait asks COMMITTED, committed scene kept on refusal, pending kept | 5.4, 7.1 | 12 |
| fold: four context rotations on corner rectangles (checked against the point-by-point reference), flip with each rotation, r = 0 c = 90 flip (1,0) to (0,1), 16 combinations as one table | 3, 5.1.4, 7.1.4, 7.1.5 | 6 |
| activation and composition: inactive at creation, activate sends the committed scene, twice no second message, deactivate, compose on active UNSUPPORTED, compose asks COMPOSED, BUSY, wait with a stale COMPOSED bit, fence, destroy waits for a pending compose | 8 | 10 |
| refusals: each service answer to its code (table 4.2), a lost device from each calling function | P5.4 | 8 |
| pure functions: `to_fixed`, `to_alpha` (ties, range, saturation) | P5.4 | 4 |

Breakages the tests must catch (P8.1): drop the clearing of the error in
`get_error` (the clearing test fails); change the sign for rotation 270 in
the fold (the corner test fails).
