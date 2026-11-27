//! Navi22 connector color state and side-effect-free TMDS admission. DRM
//! requests never acquire the asynchronous hardware owner or perform DDC.
use super::*;
use crate::amdgpu_hdr::{colorspace_valid, HdrOutputMetadata};
use crate::amdgpu_native_kms::{ConnectorColorRequest, OutputFormatRequest, OutputRoute};

impl Kms {
    pub(super) fn set_color(&mut self, request: &ConnectorColorRequest) -> bool {
        let hdr = match request.hdr_output_metadata.as_deref() {
            Some(blob) => match HdrOutputMetadata::from_blob(blob) {
                Ok(metadata) => Some(metadata),
                Err(_) => return false,
            },
            None => None,
        };
        if !colorspace_valid(u64::from(request.colorspace)) {
            return false;
        }
        let Some(index) = connector_of(self, request.connector) else {
            return false;
        };
        // amdgpu_dm attaches Colorspace and HDR_OUTPUT_METADATA to HDMI and
        // non-MST DP connectors (all of Navi22's) and accepts every listed
        // value: HDMI sends them in the AVI and Dynamic Range and Mastering
        // InfoFrames, DP in the VSC SDP and the HDR static metadata SDP.
        let connector = &mut self.connectors[index];
        let next = OutputSettings {
            color_format: request.color_format,
            colorspace: request.colorspace,
            hdr,
            ..connector.output
        };
        if next == connector.output {
            return false;
        }
        connector.output = next;
        true
    }

    pub(super) fn set_max_bpc(&mut self, connector: u32, bpc: u8) -> bool {
        if !(8..=16).contains(&bpc) {
            return false;
        }
        let Some(index) = connector_of(self, connector) else {
            return false;
        };
        let c = &mut self.connectors[index];
        // amdgpu_dm attaches "max bpc" to every non-MST connector. A DP
        // stream is 8 bpc RGB, within any cap from 8 to 16.
        if c.output.max_bpc == bpc {
            return false;
        }
        c.output.max_bpc = bpc;
        true
    }

    /// Checks the exact requested mode with the same format selector enable
    /// uses, against immutable observed EDID/board limits. Requests without a
    /// mode use the committed timing or the first admitted timing. No fallback
    /// hides an explicit unsupported color format.
    ///
    /// Joint plane admission: the planes a request is searched with are
    /// checked statically (one overlay, a GEM 8888 overlay in place,
    /// unrotated, above the primary), and the pipes the routes' planes
    /// need (one per stream, one per overlay) are budgeted against DCN30's
    /// six. The exact two-plane DML30 plan and the clock/watermark
    /// headroom stay in `display_admits_planes`, which the atomic check
    /// always runs (the format search is pitch-free and approximate).
    pub(super) fn formats_supported(
        &self,
        requests: &[OutputFormatRequest],
        routes: &[OutputRoute],
    ) -> bool {
        for (n, route) in routes.iter().enumerate() {
            if usize::from(route.display) >= MAX_CRTCS
                || connector_of(self, route.connector).is_none()
                || routes[..n]
                    .iter()
                    .any(|r| r.display == route.display || r.connector == route.connector)
            {
                return false;
            }
        }
        let mut pipes = 0u32;
        for route in routes {
            pipes += 1;
            if let Some((_, setup)) = &route.planes {
                if setup.overlay_count() > 1 {
                    return false;
                }
                pipes += setup.overlay_count() as u32;
            }
        }
        if pipes > u32::from(crate::amdgpu_navi22_modeset::PIPES) {
            return false;
        }
        requests.iter().enumerate().all(|(n, request)| {
            if requests[..n].iter().any(|r| r.connector == request.connector || r.display == request.display)
                || !routes.iter().any(|r| r.connector == request.connector && r.display == request.display)
            { return false; }
            let Some(index) = connector_of(self, request.connector) else { return false; };
            let c = &self.connectors[index];
            let max_bpc = request.max_bpc.unwrap_or(c.output.max_bpc);
            if !c.lightable() || !(8..=16).contains(&max_bpc) { return false; }
            // The planes this format is searched with: one overlay, a GEM
            // 8888 overlay in place, unrotated, above the primary (see
            // `amdgpu_navi22_plane::admit` for the same static checks).
            if let Some((_, setup)) = &request.planes {
                use crate::amdgpu_dcn401_otg::{SurfaceFormat, Tiling};
                use crate::amdgpu_dcn401_spl::Rotation;
                if setup.overlay_count() > 1 {
                    return false;
                }
                for o in setup.overlays.iter().flatten() {
                    let g = &o.geometry;
                    if !matches!(
                        o.format,
                        SurfaceFormat::Xrgb8888 | SurfaceFormat::Argb8888
                    ) || g.surface.tiling != Tiling::LINEAR
                        || g.rotation != Rotation::R0
                        || o.underlay
                        || !g.client
                    {
                        return false;
                    }
                }
            }
            // DP: RGB at the deepest depth within the cap the verified link
            // carries, down to 8 bpc, so any cap admits the stream
            // (LINUX-GAP: no YCbCr over DP).
            if c.port.signal == Signal::DisplayPort {
                return matches!(
                    request.color_format,
                    crate::amdgpu_hdr::ColorFormat::Auto | crate::amdgpu_hdr::ColorFormat::Rgb
                );
            }
            let crtc = self.crtc_at(usize::from(request.display));
            let timing = match request.mode {
                Some(mode) => self.find_mode_at(usize::from(request.display), Some(index), &mode),
                None => crtc.filter(|c| c.route == Some(index))
                    .and_then(|c| c.requested.or_else(|| c.shown.as_ref().map(|s| s.1)))
                    .or_else(|| c.modes.first().copied()),
            };
            let Some(timing) = timing else { return false; };
            let settings = OutputSettings { max_bpc, color_format: request.color_format, ..c.output };
            crate::amdgpu_dcn30_hdmi::stream_with_settings(
                &c.edid, &timing, settings,
                crate::amdgpu_navi48_boot::limited_range(crate::amdgpu_navi48_boot::broadcast_rgb()),
                c.hdmi_limits,
            ).is_some()
        })
    }
}

pub fn request_connector_color(request: ConnectorColorRequest) {
    requested(|kms| kms.set_color(&request));
}
pub fn request_connector_max_bpc(connector: u32, bpc: u8) {
    requested(|kms| kms.set_max_bpc(connector, bpc));
}
pub fn connector_color_supported(connector: u32, colorspace: u32, hdr: bool) -> bool {
    let kms = KMS.lock();
    let Some(index) = connector_of(&kms, connector) else {
        return false;
    };
    let c = &kms.connectors[index];
    colorspace_valid(u64::from(colorspace))
        && (c.port.signal != Signal::Hdmi
            || !c.present
            || crate::amdgpu_navi48_boot::hdmi_caps(&c.edid).hdmi
            || (colorspace == 0 && !hdr))
}
pub fn output_formats_supported(requests: &[OutputFormatRequest], routes: &[OutputRoute]) -> bool {
    KMS.lock().formats_supported(requests, routes)
}
