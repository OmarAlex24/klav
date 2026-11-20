//! QR codes in a PNG (a screenshot or photo of Google Authenticator's
//! export screen), with `png` and `rqrr` (ADR 0024).

use std::io::Cursor;

use png::{ColorType, Transformations};
use zeroize::Zeroizing;

use crate::ImportError;

/// Largest image read, in pixels (a 6K screenshot fits).
const MAX_PIXELS: usize = 40_000_000;

/// The text of every QR code in the image, wiped on drop (each one holds
/// TOTP secrets).
pub(crate) fn decode_png(bytes: &[u8]) -> Result<Zeroizing<Vec<String>>, ImportError> {
    let bad = |_| ImportError::Invalid("the image could not be read as a PNG".into());
    let mut decoder = png::Decoder::new(Cursor::new(bytes));
    decoder.set_transformations(Transformations::EXPAND | Transformations::STRIP_16);
    let mut reader = decoder.read_info().map_err(bad)?;
    let (w, h) = reader.info().size();
    let (w, h) = (w as usize, h as usize);
    if w.saturating_mul(h) > MAX_PIXELS {
        return Err(ImportError::TooLarge);
    }
    let size = reader
        .output_buffer_size()
        .ok_or_else(|| ImportError::Invalid("the image is too large".into()))?;
    let mut buf = Zeroizing::new(vec![0; size]);
    let info = reader.next_frame(&mut buf).map_err(bad)?;
    let channels = match info.color_type {
        ColorType::Grayscale => 1,
        ColorType::GrayscaleAlpha => 2,
        ColorType::Rgb => 3,
        ColorType::Rgba => 4,
        ColorType::Indexed => {
            return Err(ImportError::Invalid("unsupported PNG colours".into()));
        }
    };
    let stride = info.line_size;
    let luma = |x: usize, y: usize| -> u8 {
        let p = &buf[y * stride + x * channels..][..channels];
        let (v, alpha) = match channels {
            1 => (u32::from(p[0]), 255),
            2 => (u32::from(p[0]), u32::from(p[1])),
            3 => (
                (299 * u32::from(p[0]) + 587 * u32::from(p[1]) + 114 * u32::from(p[2])) / 1000,
                255,
            ),
            _ => (
                (299 * u32::from(p[0]) + 587 * u32::from(p[1]) + 114 * u32::from(p[2])) / 1000,
                u32::from(p[3]),
            ),
        };
        // Transparent pixels count as white paper.
        ((v * alpha + 255 * (255 - alpha)) / 255) as u8
    };
    let mut image = rqrr::PreparedImage::prepare_from_greyscale(w, h, luma);
    // `rqrr` keeps its own copies of the decoded bits while it works; those
    // are not wiped (a residual of reading QR images at all).
    let mut texts = Zeroizing::new(Vec::new());
    for grid in image.detect_grids() {
        if let Ok((_, text)) = grid.decode() {
            texts.push(text);
        }
    }
    if texts.is_empty() {
        return Err(ImportError::NotRecognised(
            "no QR code found in the image".into(),
        ));
    }
    Ok(texts)
}
